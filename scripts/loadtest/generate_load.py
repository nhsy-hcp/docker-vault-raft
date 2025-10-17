#!/usr/bin/env python3
"""
Vault Load Generation Script

Generates load on a Vault cluster by creating:
- Namespaces
- Leases using PKI certificates
- KV v2 engines and secrets

Uses parallel workers to speed up operations.
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
import random
import string

import hvac

# --- Global Shutdown Control ---
shutdown_event = threading.Event()


def signal_handler(signum, frame):
    """Handle shutdown signals (SIGINT, SIGTERM)"""
    logger = logging.getLogger(__name__)
    signal_name = 'SIGINT' if signum == signal.SIGINT else 'SIGTERM'
    logger.warning(f"\n{signal_name} received. Initiating graceful shutdown...")
    logger.warning("Waiting for current operations to complete. Press Ctrl+C again to force quit.")
    shutdown_event.set()


def setup_signal_handlers():
    """Register signal handlers for graceful shutdown"""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


# --- Dataclasses ---

@dataclass
class Config:
    """Configuration for load generation"""
    # Common config
    mode: str  # 'pki', 'approles', or 'kv'
    namespaces: int
    workers: int
    vault_addr: str
    vault_token: str
    vault_cacert: str
    vault_skip_verify: bool
    parent_namespace: Optional[str] = None

    # PKI lease generation config
    leases_per_namespace: int = 0
    ttl: str = '1h'
    pki_path: str = 'pki'

    # AppRole generation config
    approles_per_namespace: int = 0
    approle_ttl: str = '1h'
    approle_max_ttl: str = '24h'
    approle_path: str = 'approle'

    # KV generation config
    engines_per_namespace: int = 0
    secrets_per_engine: int = 0


@dataclass
class Stats:
    """Statistics for load generation"""
    # Common stats
    namespaces_processed: int = 0
    namespaces_created: int = 0
    namespaces_skipped: int = 0
    namespaces_failed: int = 0
    start_time: float = 0
    end_time: float = 0

    # PKI lease stats
    pki_engines_created: int = 0
    pki_engines_skipped: int = 0
    pki_engines_failed: int = 0
    cas_configured: int = 0
    cas_failed: int = 0
    roles_configured: int = 0
    roles_failed: int = 0
    leases_created: int = 0
    leases_failed: int = 0
    lease_ids: List[str] = field(default_factory=list)

    # AppRole stats
    approle_engines_created: int = 0
    approle_engines_skipped: int = 0
    approle_engines_failed: int = 0
    approles_created: int = 0
    approles_failed: int = 0
    secret_ids_generated: int = 0
    secret_ids_failed: int = 0
    approle_logins: int = 0
    approle_logins_failed: int = 0
    approle_tokens: List[str] = field(default_factory=list)

    # KV stats
    engines_created: int = 0
    engines_skipped: int = 0
    engines_failed: int = 0
    secrets_created: int = 0
    secrets_skipped: int = 0
    secrets_failed: int = 0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def total_operations(self) -> int:
        return (self.namespaces_created +
                self.pki_engines_created + self.cas_configured + self.roles_configured + self.leases_created +
                self.approle_engines_created + self.approles_created + self.secret_ids_generated + self.approle_logins +
                self.engines_created + self.secrets_created)

    @property
    def operations_per_second(self) -> float:
        if self.duration > 0:
            return self.total_operations / self.duration
        return 0

    @property
    def leases_per_second(self) -> float:
        if self.duration > 0 and self.leases_created > 0:
            return self.leases_created / self.duration
        return 0

# --- Common Functions ---

def setup_logging(level: str = "INFO"):
    """Configure logging"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def create_vault_client(config: Config, namespace: str = None) -> hvac.Client:
    """Create a Vault client"""
    # Use the provided namespace as-is
    actual_namespace = namespace if namespace else None

    client = hvac.Client(
        url=config.vault_addr,
        token=config.vault_token,
        verify=False if config.vault_skip_verify else config.vault_cacert,
        namespace=actual_namespace
    )

    if not client.is_authenticated():
        raise Exception(f"Failed to authenticate to Vault at namespace: {actual_namespace or 'root'}")

    return client


def validate_parent_namespace(config: Config) -> bool:
    """Validate that the parent namespace exists"""
    logger = logging.getLogger(__name__)

    if not config.parent_namespace:
        # No parent namespace specified, so nothing to validate
        return True

    try:
        client = hvac.Client(
            url=config.vault_addr,
            token=config.vault_token,
            verify=False if config.vault_skip_verify else config.vault_cacert,
            namespace=None  # Connect to root namespace to check if parent exists
        )

        if not client.is_authenticated():
            logger.error(f"Parent namespace validation failed: Unable to authenticate to root namespace")
            return False

        # Try to list namespaces to see if parent exists
        try:
            namespaces = client.sys.list_namespaces()
            # keys is a list of strings like ['loadtest/'], not dictionaries
            namespace_keys = namespaces.get('data', {}).get('keys', [])
            namespace_paths = [ns.rstrip('/') for ns in namespace_keys]

            if config.parent_namespace not in namespace_paths:
                logger.error(f"Parent namespace validation failed: Namespace '{config.parent_namespace}' does not exist")
                logger.error(f"Available namespaces: {', '.join(namespace_paths) if namespace_paths else 'none'}")
                return False

            logger.info(f"Parent namespace validation passed: '{config.parent_namespace}' exists")
            return True
        except Exception as e:
            error_msg = str(e).lower()
            if 'permission denied' in error_msg or 'unsupported path' in error_msg:
                # If we can't list namespaces, try to authenticate directly to the parent namespace
                try:
                    parent_client = hvac.Client(
                        url=config.vault_addr,
                        token=config.vault_token,
                        verify=False if config.vault_skip_verify else config.vault_cacert,
                        namespace=config.parent_namespace
                    )
                    if parent_client.is_authenticated():
                        logger.info(f"Parent namespace validation passed: Successfully authenticated to '{config.parent_namespace}'")
                        return True
                    else:
                        logger.error(f"Parent namespace validation failed: Cannot authenticate to '{config.parent_namespace}'")
                        return False
                except Exception as parent_e:
                    logger.error(f"Parent namespace validation failed: '{config.parent_namespace}', {parent_e}")
                    return False
            else:
                logger.error(f"Parent namespace validation failed: '{config.parent_namespace}', on list {config.vault_addr}/v1/sys/namespaces")
                return False
    except Exception as e:
        logger.error(f"Parent namespace validation failed: '{config.parent_namespace}', {e}")
        return False


def create_namespace(config: Config, namespace_path: str) -> Tuple[str, str]:
    """Create a namespace in Vault"""
    logger = logging.getLogger(__name__)

    try:
        if config.parent_namespace and '/' in namespace_path:
            parts = namespace_path.split('/')
            parent_ns = '/'.join(parts[:-1])
            child_ns = parts[-1]
            client = create_vault_client(config, namespace=parent_ns)
        else:
            client = create_vault_client(config)
            child_ns = namespace_path

        # Attempt to create the namespace
        client.sys.create_namespace(path=child_ns)
        logger.info(f"Created namespace: {namespace_path}")
        return 'created', namespace_path

    except Exception as e:
        error_msg = str(e).lower()

        # Handle namespace already exists case
        if 'already exists' in error_msg:
            logger.info(f"Namespace already exists (skipped): {namespace_path} - will use existing namespace")
            return 'skipped', namespace_path

        # Handle permission denied
        elif 'permission denied' in error_msg or 'insufficient permissions' in error_msg:
            logger.error(f"Failed to create namespace {namespace_path}: Insufficient permissions. "
                        f"Token requires 'create' capability on 'sys/namespaces/{child_ns}' path")
            return 'failed', namespace_path

        # Handle parent namespace not found
        elif 'namespace not found' in error_msg or 'no such namespace' in error_msg:
            logger.error(f"Failed to create namespace {namespace_path}: Parent namespace does not exist")
            return 'failed', namespace_path

        # Handle invalid namespace name
        elif 'invalid' in error_msg and 'name' in error_msg:
            logger.error(f"Failed to create namespace {namespace_path}: Invalid namespace name. "
                        f"Names must be alphanumeric with hyphens and underscores only")
            return 'failed', namespace_path

        # Handle other errors
        else:
            logger.error(f"Failed to create namespace {namespace_path}: {e}")
            return 'failed', namespace_path

# --- Lease Generation Functions ---

def validate_leases_in_namespace(config: Config, namespace: str) -> Tuple[int, bool]:
    """Validate that leases exist in a namespace"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        lease_path = f"sys/leases/lookup/{config.pki_path}/sign/loadtest"

        try:
            result = client.list(lease_path)
            if result and 'data' in result and 'keys' in result['data']:
                lease_count = len(result['data']['keys'])
                logger.debug(f"Found {lease_count} leases in {namespace}/{lease_path}")
                return lease_count, True
            else:
                logger.debug(f"No leases found in {namespace}/{lease_path}")
                return 0, True
        except Exception as e:
            error_msg = str(e).lower()
            if '404' in error_msg or 'not found' in error_msg:
                logger.debug(f"No leases found in {namespace}/{lease_path}")
                return 0, True
            else:
                raise
    except Exception as e:
        logger.error(f"Failed to validate leases in {namespace}: {e}")
        return 0, False


def enable_pki_engine(config: Config, namespace: str) -> Tuple[str, str]:
    """Enable PKI secrets engine in a namespace"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        client.sys.enable_secrets_engine(
            backend_type='pki',
            path=config.pki_path,
            config={'max_lease_ttl': '87600h'}
        )
        logger.info(f"Enabled PKI engine: {namespace}/{config.pki_path}")
        return 'created', namespace
    except Exception as e:
        error_msg = str(e).lower()
        if 'path is already in use' in error_msg or 'existing mount' in error_msg:
            logger.debug(f"PKI engine already exists (skipped): {namespace}/{config.pki_path}")
            return 'skipped', namespace
        else:
            logger.error(f"Failed to enable PKI engine {namespace}/{config.pki_path}: {e}")
            return 'failed', namespace


def configure_pki_ca(config: Config, namespace: str) -> Tuple[str, str]:
    """Configure PKI CA in a namespace"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        try:
            ca_cert = client.secrets.pki.read_ca_certificate(mount_point=config.pki_path)
            if ca_cert:
                logger.debug(f"PKI CA already configured (skipped): {namespace}/{config.pki_path}")
                return 'skipped', namespace
        except:
            pass
        client.secrets.pki.generate_root(
            type='internal',
            common_name=f'Load Test CA - {namespace}',
            extra_params={'ttl': '87600h'},
            mount_point=config.pki_path
        )
        logger.info(f"Configured PKI CA: {namespace}/{config.pki_path}")
        return 'configured', namespace
    except Exception as e:
        logger.error(f"Failed to configure PKI CA {namespace}/{config.pki_path}: {e}")
        return 'failed', namespace


def configure_pki_role(config: Config, namespace: str, role_name: str = 'loadtest') -> Tuple[str, str]:
    """Configure PKI role for certificate issuance"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        client.secrets.pki.create_or_update_role(
            name=role_name,
            mount_point=config.pki_path,
            extra_params={
                'allowed_domains': ['loadtest.local'],
                'allow_subdomains': True,
                'max_ttl': config.ttl,
                'ttl': config.ttl,
                'generate_lease': True
            }
        )
        logger.debug(f"Configured PKI role: {namespace}/{config.pki_path}/{role_name}")
        return 'configured', namespace
    except Exception as e:
        logger.error(f"Failed to configure PKI role {namespace}/{config.pki_path}/{role_name}: {e}")
        return 'failed', namespace


def generate_csr(common_name: str) -> Tuple[str, str]:
    """Generate a CSR and private key"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(private_key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    return csr_pem, private_key_pem


def sign_certificate(config: Config, namespace: str, cert_num: int,
                     role_name: str = 'loadtest', max_retries: int = 3) -> Tuple[str, Optional[str], str]:
    """Sign a certificate using CSR to generate a lease"""
    logger = logging.getLogger(__name__)
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    common_name = f"cert-{cert_num}-{random_suffix}.loadtest.local"

    for attempt in range(max_retries):
        try:
            csr_pem, _ = generate_csr(common_name)
            client = create_vault_client(config, namespace=namespace)
            result = client.secrets.pki.sign_certificate(
                name=role_name,
                csr=csr_pem,
                common_name=common_name,
                mount_point=config.pki_path,
                extra_params={'ttl': config.ttl}
            )
            lease_id = result.get('lease_id')
            if lease_id:
                lease_path = f"{namespace}/{config.pki_path}/sign/{role_name}"
                logger.debug(f"Created lease: {lease_path} - {common_name} (ID: {lease_id})")
                return 'created', lease_id, namespace
            else:
                logger.warning(f"Certificate signed but no lease_id: {namespace}/{config.pki_path} - {common_name}")
                return 'created', None, namespace
        except Exception as e:
            error_msg = str(e).lower()
            if 'unknown role' in error_msg and attempt < max_retries - 1:
                sleep_time = 1 * (2 ** attempt)
                logger.debug(f"Role not ready yet for {namespace}/{config.pki_path}, "
                           f"retrying in {sleep_time}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(sleep_time)
                continue
            else:
                logger.error(f"Failed to sign certificate in {namespace}/{config.pki_path}: {e}")
                return 'failed', None, namespace
    logger.error(f"Failed to sign certificate in {namespace}/{config.pki_path} after {max_retries} attempts")
    return 'failed', None, namespace


def generate_leases_for_namespace(config: Config, namespace_num: int,
                                  stats: Stats) -> Stats:
    """Generate leases for a single namespace"""
    logger = logging.getLogger(__name__)
    namespace_name = f"loadtest-{namespace_num}"
    full_namespace_path = f"{config.parent_namespace}/{namespace_name}" if config.parent_namespace else namespace_name

    # Check for shutdown before starting
    if shutdown_event.is_set():
        logger.debug(f"Skipping namespace {namespace_name} due to shutdown")
        return stats

    ns_status, _ = create_namespace(config, full_namespace_path)
    if ns_status == 'created':
        stats.namespaces_created += 1
    elif ns_status == 'skipped':
        stats.namespaces_skipped += 1
    else:
        stats.namespaces_failed += 1
        return stats

    if shutdown_event.is_set():
        return stats

    pki_status, _ = enable_pki_engine(config, full_namespace_path)
    if pki_status == 'created':
        stats.pki_engines_created += 1
    elif pki_status == 'skipped':
        stats.pki_engines_skipped += 1
    else:
        stats.pki_engines_failed += 1
        stats.namespaces_failed += 1
        return stats

    if shutdown_event.is_set():
        return stats

    ca_status, _ = configure_pki_ca(config, full_namespace_path)
    if ca_status == 'configured':
        stats.cas_configured += 1
    elif ca_status == 'skipped':
        pass
    else:
        stats.cas_failed += 1
        stats.namespaces_failed += 1
        return stats

    if shutdown_event.is_set():
        return stats

    role_status, _ = configure_pki_role(config, full_namespace_path)
    if role_status == 'configured':
        stats.roles_configured += 1
        time.sleep(0.1)
    else:
        stats.roles_failed += 1
        stats.namespaces_failed += 1
        return stats

    for cert_num in range(1, config.leases_per_namespace + 1):
        if shutdown_event.is_set():
            break

        cert_status, lease_id, _ = sign_certificate(
            config, full_namespace_path, cert_num
        )
        if cert_status == 'created':
            stats.leases_created += 1
            if lease_id:
                stats.lease_ids.append(lease_id)
        else:
            stats.leases_failed += 1

    stats.namespaces_processed += 1
    logger.info(f"Completed namespace {full_namespace_path}: "
                f"{stats.leases_created} leases created")
    return stats


def generate_all_leases(config: Config) -> Stats:
    """Generate leases across all namespaces"""
    logger = logging.getLogger(__name__)
    stats = Stats()
    stats.start_time = time.time()

    logger.info(f"Starting lease generation:")
    if config.parent_namespace:
        logger.info(f"  Parent namespace: {config.parent_namespace}")
    logger.info(f"  Namespaces: {config.namespaces}")
    logger.info(f"  Leases per namespace: {config.leases_per_namespace}")
    logger.info(f"  Lease TTL: {config.ttl}")
    logger.info(f"  Workers: {config.workers}")
    logger.info(f"  Total leases to generate: {config.namespaces * config.leases_per_namespace}")

    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        futures = [executor.submit(generate_leases_for_namespace, config, ns_num, Stats())
                   for ns_num in range(1, config.namespaces + 1)]

        completed = 0
        for future in as_completed(futures):
            # Check if shutdown was requested
            if shutdown_event.is_set():
                logger.info("Shutdown requested, waiting for running tasks to complete...")
                break

            try:
                ns_stats = future.result()
                stats.namespaces_processed += ns_stats.namespaces_processed
                stats.namespaces_created += ns_stats.namespaces_created
                stats.namespaces_skipped += ns_stats.namespaces_skipped
                stats.namespaces_failed += ns_stats.namespaces_failed
                stats.pki_engines_created += ns_stats.pki_engines_created
                stats.pki_engines_skipped += ns_stats.pki_engines_skipped
                stats.pki_engines_failed += ns_stats.pki_engines_failed
                stats.cas_configured += ns_stats.cas_configured
                stats.cas_failed += ns_stats.cas_failed
                stats.roles_configured += ns_stats.roles_configured
                stats.roles_failed += ns_stats.roles_failed
                stats.leases_created += ns_stats.leases_created
                stats.leases_failed += ns_stats.leases_failed
                stats.lease_ids.extend(ns_stats.lease_ids)

                completed += 1
                progress = (completed / config.namespaces) * 100
                logger.info(f"Progress: {completed}/{config.namespaces} "
                           f"namespaces ({progress:.1f}%) - "
                           f"{stats.leases_created} leases created")
            except Exception as e:
                logger.error(f"Task failed: {e}")
                stats.namespaces_failed += 1

        # If shutdown was requested, cancel remaining futures
        if shutdown_event.is_set():
            for future in futures:
                if not future.done():
                    future.cancel()

    stats.end_time = time.time()
    return stats


def test_pki_leases(config: Config, stats: Stats) -> dict:
    """Test and validate PKI leases across all namespaces"""
    logger = logging.getLogger(__name__)
    test_results = {
        'parent_namespace_leases': 0,
        'child_namespace_leases': {},
        'total_validated_leases': 0,
        'validation_errors': []
    }

    logger.info("")
    logger.info("=" * 60)
    logger.info("PKI LEASE VALIDATION")
    logger.info("=" * 60)

    # Validate leases in parent namespace (if it exists and leases were created there)
    if config.parent_namespace:
        logger.info(f"Validating leases in parent namespace: {config.parent_namespace}")
        parent_count, success = validate_leases_in_namespace(config, config.parent_namespace)
        if success:
            test_results['parent_namespace_leases'] = parent_count
            test_results['total_validated_leases'] += parent_count
            logger.info(f"  Found {parent_count} leases in parent namespace")
        else:
            test_results['validation_errors'].append(f"Failed to validate parent namespace: {config.parent_namespace}")

    # Validate leases in child namespaces
    logger.info(f"Validating leases in {config.namespaces} child namespaces...")
    for ns_num in range(1, config.namespaces + 1):
        namespace_name = f"loadtest-{ns_num}"
        full_namespace_path = f"{config.parent_namespace}/{namespace_name}" if config.parent_namespace else namespace_name

        lease_count, success = validate_leases_in_namespace(config, full_namespace_path)
        if success:
            test_results['child_namespace_leases'][full_namespace_path] = lease_count
            test_results['total_validated_leases'] += lease_count
            if lease_count > 0:
                logger.info(f"  {full_namespace_path}: {lease_count} leases")
        else:
            test_results['validation_errors'].append(f"Failed to validate namespace: {full_namespace_path}")

    # Summary
    logger.info("")
    logger.info("Validation Summary:")
    logger.info(f"  Total leases validated: {test_results['total_validated_leases']}")
    logger.info(f"  Leases created by script: {stats.leases_created}")
    logger.info(f"  Match: {'✓ YES' if test_results['total_validated_leases'] >= stats.leases_created else '✗ NO'}")

    if test_results['validation_errors']:
        logger.warning(f"  Validation errors: {len(test_results['validation_errors'])}")
        for error in test_results['validation_errors']:
            logger.warning(f"    - {error}")

    logger.info("=" * 60)
    return test_results

# --- AppRole Generation Functions ---

def enable_approle_engine(config: Config, namespace: str) -> Tuple[str, str]:
    """Enable AppRole auth method in a namespace"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        client.sys.enable_auth_method(
            method_type='approle',
            path=config.approle_path
        )
        logger.info(f"Enabled AppRole engine: {namespace}/{config.approle_path}")
        return 'created', namespace
    except Exception as e:
        error_msg = str(e).lower()
        if 'path is already in use' in error_msg or 'existing mount' in error_msg:
            logger.debug(f"AppRole engine already exists (skipped): {namespace}/{config.approle_path}")
            return 'skipped', namespace
        else:
            logger.error(f"Failed to enable AppRole engine {namespace}/{config.approle_path}: {e}")
            return 'failed', namespace


def create_approle_role(config: Config, namespace: str, role_name: str) -> Tuple[str, str]:
    """Create an AppRole role with specified TTL settings"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        role_path = f"auth/{config.approle_path}/role/{role_name}"

        client.write(
            role_path,
            bind_secret_id=True,
            token_ttl=config.approle_ttl,
            token_max_ttl=config.approle_max_ttl,
            token_policies=["default"]
        )
        logger.debug(f"Created AppRole: {namespace}/{config.approle_path}/{role_name}")
        return 'created', namespace
    except Exception as e:
        logger.error(f"Failed to create AppRole {namespace}/{config.approle_path}/{role_name}: {e}")
        return 'failed', namespace


def get_approle_role_id(config: Config, namespace: str, role_name: str) -> Tuple[str, Optional[str], str]:
    """Get the role_id for an AppRole"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        role_id_path = f"auth/{config.approle_path}/role/{role_name}/role-id"

        result = client.read(role_id_path)
        if result and 'data' in result and 'role_id' in result['data']:
            role_id = result['data']['role_id']
            logger.debug(f"Retrieved role_id for {namespace}/{config.approle_path}/{role_name}")
            return 'success', role_id, namespace
        else:
            logger.error(f"No role_id found for {namespace}/{config.approle_path}/{role_name}")
            return 'failed', None, namespace
    except Exception as e:
        logger.error(f"Failed to get role_id for {namespace}/{config.approle_path}/{role_name}: {e}")
        return 'failed', None, namespace


def generate_secret_id(config: Config, namespace: str, role_name: str) -> Tuple[str, Optional[str], str]:
    """Generate a secret_id for an AppRole"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        secret_id_path = f"auth/{config.approle_path}/role/{role_name}/secret-id"

        result = client.write(secret_id_path)
        if result and 'data' in result and 'secret_id' in result['data']:
            secret_id = result['data']['secret_id']
            logger.debug(f"Generated secret_id for {namespace}/{config.approle_path}/{role_name}")
            return 'created', secret_id, namespace
        else:
            logger.error(f"No secret_id in response for {namespace}/{config.approle_path}/{role_name}")
            return 'failed', None, namespace
    except Exception as e:
        logger.error(f"Failed to generate secret_id for {namespace}/{config.approle_path}/{role_name}: {e}")
        return 'failed', None, namespace


def approle_login(config: Config, namespace: str, role_id: str, secret_id: str) -> Tuple[str, Optional[str], str]:
    """Login with AppRole credentials to generate a token lease"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        login_path = f"auth/{config.approle_path}/login"

        result = client.write(login_path, role_id=role_id, secret_id=secret_id)
        if result and 'auth' in result and 'client_token' in result['auth']:
            token = result['auth']['client_token']
            logger.debug(f"Successful AppRole login for {namespace}/{config.approle_path}")
            return 'success', token, namespace
        else:
            logger.error(f"No client_token in login response for {namespace}/{config.approle_path}")
            return 'failed', None, namespace
    except Exception as e:
        logger.error(f"Failed AppRole login for {namespace}/{config.approle_path}: {e}")
        return 'failed', None, namespace


def generate_approles_for_namespace(config: Config, namespace_num: int, stats: Stats) -> Stats:
    """Generate AppRoles for a single namespace"""
    logger = logging.getLogger(__name__)
    namespace_name = f"loadtest-{namespace_num}"
    full_namespace_path = f"{config.parent_namespace}/{namespace_name}" if config.parent_namespace else namespace_name

    # Check for shutdown before starting
    if shutdown_event.is_set():
        logger.debug(f"Skipping namespace {namespace_name} due to shutdown")
        return stats

    ns_status, _ = create_namespace(config, full_namespace_path)
    if ns_status == 'created':
        stats.namespaces_created += 1
    elif ns_status == 'skipped':
        stats.namespaces_skipped += 1
    else:
        stats.namespaces_failed += 1
        return stats

    if shutdown_event.is_set():
        return stats

    approle_status, _ = enable_approle_engine(config, full_namespace_path)
    if approle_status == 'created':
        stats.approle_engines_created += 1
    elif approle_status == 'skipped':
        stats.approle_engines_skipped += 1
    else:
        stats.approle_engines_failed += 1
        stats.namespaces_failed += 1
        return stats

    for approle_num in range(1, config.approles_per_namespace + 1):
        if shutdown_event.is_set():
            break

        role_name = f"loadtest-{approle_num}"

        # Create AppRole
        role_status, _ = create_approle_role(config, full_namespace_path, role_name)
        if role_status == 'created':
            stats.approles_created += 1
        else:
            stats.approles_failed += 1
            continue

        # Get role_id
        role_id_status, role_id, _ = get_approle_role_id(config, full_namespace_path, role_name)
        if role_id_status != 'success' or not role_id:
            stats.approles_failed += 1
            continue

        # Generate secret_id
        secret_id_status, secret_id, _ = generate_secret_id(config, full_namespace_path, role_name)
        if secret_id_status == 'created' and secret_id:
            stats.secret_ids_generated += 1
        else:
            stats.secret_ids_failed += 1
            continue

        # Login to generate token
        login_status, token, _ = approle_login(config, full_namespace_path, role_id, secret_id)
        if login_status == 'success' and token:
            stats.approle_logins += 1
            stats.approle_tokens.append(token)
        else:
            stats.approle_logins_failed += 1

    stats.namespaces_processed += 1
    logger.info(f"Completed namespace {full_namespace_path}: "
                f"{stats.approles_created} approles, {stats.approle_logins} logins")
    return stats


def generate_all_approles(config: Config) -> Stats:
    """Generate AppRoles across all namespaces"""
    logger = logging.getLogger(__name__)
    stats = Stats()
    stats.start_time = time.time()

    logger.info(f"Starting AppRole generation:")
    if config.parent_namespace:
        logger.info(f"  Parent namespace: {config.parent_namespace}")
    logger.info(f"  Namespaces: {config.namespaces}")
    logger.info(f"  AppRoles per namespace: {config.approles_per_namespace}")
    logger.info(f"  AppRole token TTL: {config.approle_ttl}")
    logger.info(f"  AppRole token max TTL: {config.approle_max_ttl}")
    logger.info(f"  Workers: {config.workers}")
    logger.info(f"  Total AppRoles to generate: {config.namespaces * config.approles_per_namespace}")

    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        futures = [executor.submit(generate_approles_for_namespace, config, ns_num, Stats())
                   for ns_num in range(1, config.namespaces + 1)]

        completed = 0
        for future in as_completed(futures):
            # Check if shutdown was requested
            if shutdown_event.is_set():
                logger.info("Shutdown requested, waiting for running tasks to complete...")
                break

            try:
                ns_stats = future.result()
                stats.namespaces_processed += ns_stats.namespaces_processed
                stats.namespaces_created += ns_stats.namespaces_created
                stats.namespaces_skipped += ns_stats.namespaces_skipped
                stats.namespaces_failed += ns_stats.namespaces_failed
                stats.approle_engines_created += ns_stats.approle_engines_created
                stats.approle_engines_skipped += ns_stats.approle_engines_skipped
                stats.approle_engines_failed += ns_stats.approle_engines_failed
                stats.approles_created += ns_stats.approles_created
                stats.approles_failed += ns_stats.approles_failed
                stats.secret_ids_generated += ns_stats.secret_ids_generated
                stats.secret_ids_failed += ns_stats.secret_ids_failed
                stats.approle_logins += ns_stats.approle_logins
                stats.approle_logins_failed += ns_stats.approle_logins_failed
                stats.approle_tokens.extend(ns_stats.approle_tokens)

                completed += 1
                progress = (completed / config.namespaces) * 100
                logger.info(f"Progress: {completed}/{config.namespaces} "
                           f"namespaces ({progress:.1f}%) - "
                           f"{stats.approle_logins} logins completed")
            except Exception as e:
                logger.error(f"Task failed: {e}")
                stats.namespaces_failed += 1

        # If shutdown was requested, cancel remaining futures
        if shutdown_event.is_set():
            for future in futures:
                if not future.done():
                    future.cancel()

    stats.end_time = time.time()
    return stats


# --- KV Generation Functions ---

def generate_random_secret_data(num_keys: int = 5) -> dict:
    """Generate random secret data"""
    data = {}
    for i in range(num_keys):
        key = f"key_{i+1}"
        value = ''.join(random.choices(
            string.ascii_letters + string.digits,
            k=random.randint(16, 64)
        ))
        data[key] = value
    data['generated_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
    data['description'] = f"Load test secret with {num_keys} keys"
    return data


def create_kv_engine(config: Config, namespace: str, engine_name: str) -> Tuple[str, str, str]:
    """Create a KV v2 engine in a namespace"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        client.sys.enable_secrets_engine(
            backend_type='kv',
            path=engine_name,
            options={'version': '2'}
        )
        logger.info(f"Created KV v2 engine: {namespace}/{engine_name}")
        return 'created', namespace, engine_name
    except Exception as e:
        error_msg = str(e).lower()
        if 'path is already in use' in error_msg or 'existing mount' in error_msg:
            logger.debug(f"KV engine already exists (skipped): {namespace}/{engine_name}")
            return 'skipped', namespace, engine_name
        else:
            logger.error(f"Failed to create engine {namespace}/{engine_name}: {e}")
            return 'failed', namespace, engine_name


def write_secret(config: Config, namespace: str, engine_name: str,
                secret_path: str) -> Tuple[str, str, str, str]:
    """Write a secret to a KV v2 engine"""
    logger = logging.getLogger(__name__)
    try:
        client = create_vault_client(config, namespace=namespace)
        try:
            existing = client.secrets.kv.v2.read_secret_version(
                path=secret_path,
                mount_point=engine_name,
                raise_on_deleted_version=False
            )
            if existing:
                logger.debug(f"Secret already exists (skipped): {namespace}/{engine_name}/{secret_path}")
                return 'skipped', namespace, engine_name, secret_path
        except:
            pass
        secret_data = generate_random_secret_data()
        client.secrets.kv.v2.create_or_update_secret(
            path=secret_path,
            secret=secret_data,
            mount_point=engine_name
        )
        logger.debug(f"Wrote secret: {namespace}/{engine_name}/{secret_path}")
        return 'created', namespace, engine_name, secret_path
    except Exception as e:
        logger.error(f"Failed to write secret {namespace}/{engine_name}/{secret_path}: {e}")
        return 'failed', namespace, engine_name, secret_path


def create_namespace_with_engines(config: Config, namespace_num: int,
                                  stats: Stats) -> Stats:
    """Create a namespace with all its engines and secrets"""
    logger = logging.getLogger(__name__)
    namespace_name = f"loadtest-{namespace_num}"
    full_namespace_path = f"{config.parent_namespace}/{namespace_name}" if config.parent_namespace else namespace_name

    # Check for shutdown before starting
    if shutdown_event.is_set():
        logger.debug(f"Skipping namespace {namespace_name} due to shutdown")
        return stats

    status, _ = create_namespace(config, full_namespace_path)
    if status == 'created':
        stats.namespaces_created += 1
    elif status == 'skipped':
        stats.namespaces_skipped += 1
    else:
        stats.namespaces_failed += 1
        return stats

    for engine_num in range(1, config.engines_per_namespace + 1):
        if shutdown_event.is_set():
            break

        engine_name = f"kv-{engine_num}"
        status, _, _ = create_kv_engine(config, full_namespace_path, engine_name)
        if status == 'created':
            stats.engines_created += 1
        elif status == 'skipped':
            stats.engines_skipped += 1
        else:
            stats.engines_failed += 1
            continue

        for secret_num in range(1, config.secrets_per_engine + 1):
            if shutdown_event.is_set():
                break

            secret_path = f"secret-{secret_num}"
            status, _, _, _ = write_secret(
                config, full_namespace_path, engine_name, secret_path
            )
            if status == 'created':
                stats.secrets_created += 1
            elif status == 'skipped':
                stats.secrets_skipped += 1
            else:
                stats.secrets_failed += 1

    stats.namespaces_processed += 1
    logger.info(f"Completed namespace {namespace_name}: "
                f"{stats.engines_created + stats.engines_skipped} engines, "
                f"{stats.secrets_created + stats.secrets_skipped} secrets")
    return stats


def generate_kv_load(config: Config) -> Stats:
    """Generate KV load on Vault cluster"""
    logger = logging.getLogger(__name__)
    stats = Stats()
    stats.start_time = time.time()

    logger.info(f"Starting KV load generation:")
    if config.parent_namespace:
        logger.info(f"  Parent namespace: {config.parent_namespace}")
    logger.info(f"  Namespaces: {config.namespaces}")
    logger.info(f"  Engines per namespace: {config.engines_per_namespace}")
    logger.info(f"  Secrets per engine: {config.secrets_per_engine}")
    logger.info(f"  Workers: {config.workers}")
    logger.info(f"  Total operations: {config.namespaces} namespaces, "
                f"{config.namespaces * config.engines_per_namespace} engines, "
                f"{config.namespaces * config.engines_per_namespace * config.secrets_per_engine} secrets")

    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        futures = [executor.submit(create_namespace_with_engines, config, ns_num, Stats())
                   for ns_num in range(1, config.namespaces + 1)]

        completed = 0
        for future in as_completed(futures):
            # Check if shutdown was requested
            if shutdown_event.is_set():
                logger.info("Shutdown requested, waiting for running tasks to complete...")
                break

            try:
                ns_stats = future.result()
                stats.namespaces_created += ns_stats.namespaces_created
                stats.namespaces_skipped += ns_stats.namespaces_skipped
                stats.namespaces_failed += ns_stats.namespaces_failed
                stats.engines_created += ns_stats.engines_created
                stats.engines_skipped += ns_stats.engines_skipped
                stats.engines_failed += ns_stats.engines_failed
                stats.secrets_created += ns_stats.secrets_created
                stats.secrets_skipped += ns_stats.secrets_skipped
                stats.secrets_failed += ns_stats.secrets_failed
                stats.namespaces_processed += ns_stats.namespaces_processed

                completed += 1
                progress = (completed / config.namespaces) * 100
                logger.info(f"Progress: {completed}/{config.namespaces} "
                           f"namespaces ({progress:.1f}%)")
            except Exception as e:
                logger.error(f"Task failed: {e}")
                stats.namespaces_failed += 1

        # If shutdown was requested, cancel remaining futures
        if shutdown_event.is_set():
            for future in futures:
                if not future.done():
                    future.cancel()

    stats.end_time = time.time()
    return stats

# --- Summary and Main ---

def print_summary(config: Config, stats: Stats):
    """Print summary statistics"""
    logger = logging.getLogger(__name__)

    logger.info("")
    logger.info("=" * 60)
    logger.info("LOAD GENERATION SUMMARY")
    logger.info("=" * 60)
    logger.info("")
    logger.info("Configuration:")
    logger.info(f"  Mode: {config.mode}")
    if config.parent_namespace:
        logger.info(f"  Parent namespace: {config.parent_namespace}")
    logger.info(f"  Namespaces: {config.namespaces}")
    logger.info(f"  Workers: {config.workers}")

    if config.mode == 'pki':
        logger.info(f"  Leases per namespace: {config.leases_per_namespace}")
        logger.info(f"  Lease TTL: {config.ttl}")
    elif config.mode == 'approles':
        logger.info(f"  AppRoles per namespace: {config.approles_per_namespace}")
        logger.info(f"  AppRole token TTL: {config.approle_ttl}")
        logger.info(f"  AppRole token max TTL: {config.approle_max_ttl}")
    elif config.mode == 'kv':
        logger.info(f"  Engines per namespace: {config.engines_per_namespace}")
        logger.info(f"  Secrets per engine: {config.secrets_per_engine}")

    logger.info("")
    logger.info("Results:")
    logger.info(f"  Namespaces processed: {stats.namespaces_processed}")
    logger.info(f"  Namespaces created: {stats.namespaces_created}")
    logger.info(f"  Namespaces skipped: {stats.namespaces_skipped}")
    logger.info(f"  Namespaces failed: {stats.namespaces_failed}")

    if config.mode == 'pki':
        logger.info(f"  PKI engines created: {stats.pki_engines_created}")
        logger.info(f"  PKI engines skipped: {stats.pki_engines_skipped}")
        logger.info(f"  PKI engines failed: {stats.pki_engines_failed}")
        logger.info(f"  CAs configured: {stats.cas_configured}")
        logger.info(f"  CAs failed: {stats.cas_failed}")
        logger.info(f"  Roles configured: {stats.roles_configured}")
        logger.info(f"  Roles failed: {stats.roles_failed}")
        logger.info(f"  Leases created: {stats.leases_created}")
        logger.info(f"  Leases failed: {stats.leases_failed}")
    elif config.mode == 'approles':
        logger.info(f"  AppRole engines created: {stats.approle_engines_created}")
        logger.info(f"  AppRole engines skipped: {stats.approle_engines_skipped}")
        logger.info(f"  AppRole engines failed: {stats.approle_engines_failed}")
        logger.info(f"  AppRoles created: {stats.approles_created}")
        logger.info(f"  AppRoles failed: {stats.approles_failed}")
        logger.info(f"  Secret IDs generated: {stats.secret_ids_generated}")
        logger.info(f"  Secret IDs failed: {stats.secret_ids_failed}")
        logger.info(f"  AppRole logins: {stats.approle_logins}")
        logger.info(f"  AppRole logins failed: {stats.approle_logins_failed}")
    elif config.mode == 'kv':
        logger.info(f"  Engines created: {stats.engines_created}")
        logger.info(f"  Engines skipped: {stats.engines_skipped}")
        logger.info(f"  Engines failed: {stats.engines_failed}")
        logger.info(f"  Secrets created: {stats.secrets_created}")
        logger.info(f"  Secrets skipped: {stats.secrets_skipped}")
        logger.info(f"  Secrets failed: {stats.secrets_failed}")

    logger.info("")
    logger.info("Performance:")
    logger.info(f"  Duration: {stats.duration:.2f} seconds")
    logger.info(f"  Operations per second: {stats.operations_per_second:.2f}")
    if config.mode == 'pki':
        logger.info(f"  Leases per second: {stats.leases_per_second:.2f}")
    logger.info("")
    logger.info("=" * 60)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='''
Generate load on a Vault cluster by creating namespaces, PKI leases, or KV secrets.

The script validates authentication, verifies parent namespace existence, and provides
detailed statistics on operations performed. All operations are idempotent - existing
resources are skipped automatically.

Examples:
  # Generate 1000 PKI leases (10 namespaces × 100 leases each)
  python3 generate_load.py --namespaces 10 pki --leases-per-namespace 100

  # Generate 500 AppRole token leases (10 namespaces × 50 approles each)
  python3 generate_load.py --namespaces 10 approles --approles-per-namespace 50

  # Generate 1000 KV secrets (10 namespaces × 10 engines × 10 secrets)
  python3 generate_load.py --namespaces 10 kv --engines-per-namespace 10 --secrets-per-engine 10

  # Use custom parent namespace with 8 workers
  python3 generate_load.py --parent-namespace prod --workers 8 pki --leases-per-namespace 50
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Environment Variables:
  VAULT_ADDR            Vault server address (default: https://localhost:8200)
  VAULT_TOKEN           Vault authentication token (required)
  VAULT_CACERT          Path to CA certificate for TLS verification
  VAULT_SKIP_VERIFY     Skip TLS certificate verification (not recommended)
  VAULT_NAMESPACE       Parent namespace for load generation (default: loadtest)

Validation Checks:
  1. VAULT_TOKEN is provided via environment variable or --vault-token
  2. Token successfully authenticates with Vault
  3. Parent namespace exists and is accessible
  4. All validation errors exit with clear error messages

Performance:
  - Uses parallel workers (default: 4) for concurrent operations
  - Lease generation: ~10-15 leases/second (PKI certificate signing)
  - KV generation: ~40-50 operations/second (namespace + engine + secret creation)
        '''
    )
    # Common arguments
    parser.add_argument('--vault-addr',
                       default=os.getenv('VAULT_ADDR', 'https://localhost:8200'),
                       help='Vault server address (default: VAULT_ADDR env var or https://localhost:8200)')
    parser.add_argument('--vault-token',
                       default=os.getenv('VAULT_TOKEN'),
                       help='Vault authentication token (required, default: VAULT_TOKEN env var)')
    parser.add_argument('--vault-cacert',
                       default=os.getenv('VAULT_CACERT'),
                       help='Path to CA certificate for TLS verification (default: VAULT_CACERT env var)')
    parser.add_argument('--vault-skip-verify',
                       action='store_true',
                       default=os.getenv('VAULT_SKIP_VERIFY', 'false').lower() == 'true',
                       help='Skip TLS certificate verification (not recommended for production)')
    parser.add_argument('--log-level',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO',
                       help='Logging verbosity level (default: INFO)')
    parser.add_argument('--parent-namespace',
                       default=os.getenv('VAULT_NAMESPACE', 'loadtest'),
                       help='Parent namespace to create child namespaces under (default: VAULT_NAMESPACE env var or "loadtest")')
    parser.add_argument('--workers',
                       type=int,
                       default=4,
                       help='Number of parallel worker threads for concurrent operations (default: 4)')
    parser.add_argument('--namespaces',
                       type=int,
                       default=5,
                       help='Number of child namespaces to create under parent namespace (default: 5)')

    subparsers = parser.add_subparsers(dest='mode', required=True, help='Load generation mode (required)')

    # PKI mode
    parser_pki = subparsers.add_parser(
        'pki',
        help='Generate load by creating PKI certificate leases',
        description='Creates PKI secrets engines, configures CAs and roles, then generates certificate leases',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser_pki.add_argument('--leases-per-namespace',
                              type=int,
                              default=10,
                              help='Number of PKI certificate leases to generate per namespace (default: 10)')
    parser_pki.add_argument('--ttl',
                              default='1h',
                              help='Lease time-to-live duration (examples: 1h, 30m, 24h, default: 1h)')
    parser_pki.add_argument('--pki-path',
                              default='pki',
                              help='PKI secrets engine mount path (default: pki)')

    # AppRoles mode
    parser_approles = subparsers.add_parser(
        'approles',
        help='Generate load by creating AppRole authentications with token leases',
        description='Creates AppRole auth methods, generates roles with secret IDs, and performs logins to create token leases',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser_approles.add_argument('--approles-per-namespace',
                                type=int,
                                default=10,
                                help='Number of AppRoles to create per namespace (default: 10)')
    parser_approles.add_argument('--approle-ttl',
                                default='1h',
                                help='AppRole token TTL (examples: 1h, 30m, 24h, default: 1h)')
    parser_approles.add_argument('--approle-max-ttl',
                                default='24h',
                                help='AppRole token maximum TTL (default: 24h)')
    parser_approles.add_argument('--approle-path',
                                default='approle',
                                help='AppRole auth method mount path (default: approle)')

    # KV mode
    parser_kv = subparsers.add_parser(
        'kv',
        help='Generate load by creating KV v2 secrets',
        description='Creates KV v2 secrets engines and populates them with random secrets',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser_kv.add_argument('--engines-per-namespace',
                          type=int,
                          default=3,
                          help='Number of KV v2 engines to create per namespace (default: 3)')
    parser_kv.add_argument('--secrets-per-engine',
                          type=int,
                          default=10,
                          help='Number of secrets to write to each KV engine (default: 10)')

    args = parser.parse_args()

    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    # Register signal handlers for graceful shutdown
    setup_signal_handlers()

    if args.vault_skip_verify:
        warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    if not args.vault_token:
        logger.error("VAULT_TOKEN validation failed: Token not provided. Set VAULT_TOKEN environment variable or use --vault-token argument")
        sys.exit(1)

    logger.info(f"VAULT_TOKEN validation passed")

    config = Config(
        mode=args.mode,
        namespaces=args.namespaces,
        workers=args.workers,
        vault_addr=args.vault_addr,
        vault_token=args.vault_token,
        vault_cacert=args.vault_cacert,
        vault_skip_verify=args.vault_skip_verify,
        parent_namespace=args.parent_namespace
    )

    if args.mode == 'pki':
        config.leases_per_namespace = args.leases_per_namespace
        config.ttl = args.ttl
        config.pki_path = args.pki_path
    elif args.mode == 'approles':
        config.approles_per_namespace = args.approles_per_namespace
        config.approle_ttl = args.approle_ttl
        config.approle_max_ttl = args.approle_max_ttl
        config.approle_path = args.approle_path
    elif args.mode == 'kv':
        config.engines_per_namespace = args.engines_per_namespace
        config.secrets_per_engine = args.secrets_per_engine

    try:
        logger.info(f"Validating Vault authentication at {config.vault_addr}...")
        client = create_vault_client(config)
        if not client.is_authenticated():
            logger.error("Authentication validation failed: Token is not valid or has insufficient permissions")
            sys.exit(1)
        logger.info("Authentication validation passed: Successfully connected to Vault")
    except Exception as e:
        logger.error(f"Authentication validation failed: {e}")
        sys.exit(1)

    # Validate parent namespace exists
    if not validate_parent_namespace(config):
        sys.exit(1)

    try:
        stats = None
        if config.mode == 'pki':
            stats = generate_all_leases(config)

            # If shutdown was requested, print partial summary
            if shutdown_event.is_set():
                logger.warning("")
                logger.warning("=" * 60)
                logger.warning("PARTIAL RESULTS (Shutdown requested)")
                logger.warning("=" * 60)
                print_summary(config, stats)
                sys.exit(130)  # Standard exit code for SIGINT

            # Validate and test PKI leases
            if stats and stats.leases_created > 0:
                test_pki_leases(config, stats)

        elif config.mode == 'approles':
            stats = generate_all_approles(config)

            # If shutdown was requested, print partial summary
            if shutdown_event.is_set():
                logger.warning("")
                logger.warning("=" * 60)
                logger.warning("PARTIAL RESULTS (Shutdown requested)")
                logger.warning("=" * 60)
                print_summary(config, stats)
                sys.exit(130)  # Standard exit code for SIGINT

        elif config.mode == 'kv':
            stats = generate_kv_load(config)

            # If shutdown was requested, print partial summary
            if shutdown_event.is_set():
                logger.warning("")
                logger.warning("=" * 60)
                logger.warning("PARTIAL RESULTS (Shutdown requested)")
                logger.warning("=" * 60)
                print_summary(config, stats)
                sys.exit(130)  # Standard exit code for SIGINT

        if stats:
            print_summary(config, stats)
            if stats.namespaces_failed > 0 or stats.leases_failed > 0 or stats.secrets_failed > 0:
                sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("\nForced shutdown (second Ctrl+C)")
        if stats:
            logger.warning("")
            logger.warning("=" * 60)
            logger.warning("PARTIAL RESULTS (Forced shutdown)")
            logger.warning("=" * 60)
            print_summary(config, stats)
        sys.exit(130)
    except Exception as e:
        logger.error(f"Load generation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
