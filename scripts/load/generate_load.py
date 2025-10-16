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
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
import random
import string

import hvac
from dotenv import load_dotenv

# --- Dataclasses ---

@dataclass
class Config:
    """Configuration for load generation"""
    # Common config
    mode: str  # 'leases' or 'kv'
    namespaces: int
    workers: int
    vault_addr: str
    vault_token: str
    vault_cacert: str
    vault_skip_verify: bool
    parent_namespace: Optional[str] = None

    # Lease generation config
    leases_per_namespace: int = 0
    ttl: str = '1h'
    pki_path: str = 'pki'

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

    # Lease stats
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
    if namespace and config.parent_namespace:
        actual_namespace = config.parent_namespace
    elif namespace:
        actual_namespace = namespace
    else:
        actual_namespace = None

    client = hvac.Client(
        url=config.vault_addr,
        token=config.vault_token,
        verify=False if config.vault_skip_verify else config.vault_cacert,
        namespace=actual_namespace
    )

    if not client.is_authenticated():
        raise Exception(f"Failed to authenticate to Vault at namespace: {actual_namespace or 'root'}")

    return client


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

        client.sys.create_namespace(path=child_ns)
        logger.info(f"Created namespace: {namespace_path}")
        return 'created', namespace_path

    except Exception as e:
        error_msg = str(e).lower()
        if 'namespace already exists' in error_msg or 'existing namespace' in error_msg:
            logger.debug(f"Namespace already exists (skipped): {namespace_path}")
            return 'skipped', namespace_path
        else:
            logger.error(f"Failed to create namespace {namespace_path}: {e}")
            return 'failed', namespace_path

# --- Lease Generation Functions ---

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
                logger.debug(f"Signed certificate: {namespace}/{config.pki_path} - {common_name} (lease: {lease_id})")
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
                logger.error(f"Failed to sign certificate {namespace}/{config.pki_path}: {e}")
                return 'failed', None, namespace
    logger.error(f"Failed to sign certificate {namespace}/{config.pki_path} after {max_retries} attempts")
    return 'failed', None, namespace


def generate_leases_for_namespace(config: Config, namespace_num: int,
                                  stats: Stats) -> Stats:
    """Generate leases for a single namespace"""
    logger = logging.getLogger(__name__)
    namespace_name = f"load-test-ns-{namespace_num}"
    full_namespace_path = f"{config.parent_namespace}/{namespace_name}" if config.parent_namespace else namespace_name

    ns_status, _ = create_namespace(config, full_namespace_path)
    if ns_status == 'created':
        stats.namespaces_created += 1
    elif ns_status == 'skipped':
        stats.namespaces_skipped += 1
    else:
        stats.namespaces_failed += 1
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

    ca_status, _ = configure_pki_ca(config, full_namespace_path)
    if ca_status == 'configured':
        stats.cas_configured += 1
    elif ca_status == 'skipped':
        pass
    else:
        stats.cas_failed += 1
        stats.namespaces_failed += 1
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
    logger.info(f"Completed namespace {namespace_name}: "
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
    namespace_name = f"load-test-ns-{namespace_num}"
    full_namespace_path = f"{config.parent_namespace}/{namespace_name}" if config.parent_namespace else namespace_name

    status, _ = create_namespace(config, full_namespace_path)
    if status == 'created':
        stats.namespaces_created += 1
    elif status == 'skipped':
        stats.namespaces_skipped += 1
    else:
        stats.namespaces_failed += 1
        return stats

    for engine_num in range(1, config.engines_per_namespace + 1):
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

    if config.mode == 'leases':
        logger.info(f"  Leases per namespace: {config.leases_per_namespace}")
        logger.info(f"  Lease TTL: {config.ttl}")
    elif config.mode == 'kv':
        logger.info(f"  Engines per namespace: {config.engines_per_namespace}")
        logger.info(f"  Secrets per engine: {config.secrets_per_engine}")

    logger.info("")
    logger.info("Results:")
    logger.info(f"  Namespaces processed: {stats.namespaces_processed}")
    logger.info(f"  Namespaces created: {stats.namespaces_created}")
    logger.info(f"  Namespaces skipped: {stats.namespaces_skipped}")
    logger.info(f"  Namespaces failed: {stats.namespaces_failed}")

    if config.mode == 'leases':
        logger.info(f"  PKI engines created: {stats.pki_engines_created}")
        logger.info(f"  PKI engines skipped: {stats.pki_engines_skipped}")
        logger.info(f"  PKI engines failed: {stats.pki_engines_failed}")
        logger.info(f"  CAs configured: {stats.cas_configured}")
        logger.info(f"  CAs failed: {stats.cas_failed}")
        logger.info(f"  Roles configured: {stats.roles_configured}")
        logger.info(f"  Roles failed: {stats.roles_failed}")
        logger.info(f"  Leases created: {stats.leases_created}")
        logger.info(f"  Leases failed: {stats.leases_failed}")
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
    if config.mode == 'leases':
        logger.info(f"  Leases per second: {stats.leases_per_second:.2f}")
    logger.info("")
    logger.info("=" * 60)


def main():
    """Main entry point"""
    load_dotenv()

    parser = argparse.ArgumentParser(
        description='Generate load on a Vault cluster.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # Common arguments
    parser.add_argument('--vault-addr', default=os.getenv('VAULT_ADDR', 'https://localhost:8200'), help='Vault address')
    parser.add_argument('--vault-token', default=os.getenv('VAULT_TOKEN'), help='Vault token')
    parser.add_argument('--vault-cacert', default=os.getenv('VAULT_CACERT'), help='Path to CA certificate')
    parser.add_argument('--vault-skip-verify', action='store_true', default=os.getenv('VAULT_SKIP_VERIFY', 'false').lower() == 'true', help='Skip TLS verification')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='Logging level')
    parser.add_argument('--parent-namespace', default=os.getenv('VAULT_NAMESPACE', 'loadtest'), help='Parent namespace to create child namespaces under')
    parser.add_argument('--workers', type=int, default=4, help='Number of parallel workers/threads')
    parser.add_argument('--namespaces', type=int, default=5, help='Number of namespaces to use')
    parser.add_argument('--no-token', action='store_true', help='Run in test mode without a token')

    subparsers = parser.add_subparsers(dest='mode', required=True, help='Load generation mode')

    # Leases mode
    parser_leases = subparsers.add_parser('leases', help='Generate load by creating PKI leases', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser_leases.add_argument('--leases-per-namespace', type=int, default=10, help='Number of leases (certificates) to generate per namespace')
    parser_leases.add_argument('--ttl', default='1h', help='Lease TTL (e.g., 1h, 30m, 24h)')
    parser_leases.add_argument('--pki-path', default='pki', help='PKI secrets engine mount path')

    # KV mode
    parser_kv = subparsers.add_parser('kv', help='Generate load by creating KV secrets', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser_kv.add_argument('--engines-per-namespace', type=int, default=3, help='Number of KV v2 engines per namespace')
    parser_kv.add_argument('--secrets-per-engine', type=int, default=10, help='Number of secrets to create per engine')

    args = parser.parse_args()

    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    if args.no_token:
        logger.info("Running in test mode with --no-token. Exiting.")
        sys.exit(0)

    if args.vault_skip_verify:
        warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    if not args.vault_token:
        logger.error("Vault token not provided. Set VAULT_TOKEN or use --vault-token")
        sys.exit(1)

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

    if args.mode == 'leases':
        config.leases_per_namespace = args.leases_per_namespace
        config.ttl = args.ttl
        config.pki_path = args.pki_path
    elif args.mode == 'kv':
        config.engines_per_namespace = args.engines_per_namespace
        config.secrets_per_engine = args.secrets_per_engine

    try:
        logger.info(f"Testing connection to Vault at {config.vault_addr}...")
        client = create_vault_client(config)
        logger.info("Successfully connected to Vault")
    except Exception as e:
        logger.error(f"Failed to connect to Vault: {e}")
        sys.exit(1)

    try:
        stats = None
        if config.mode == 'leases':
            stats = generate_all_leases(config)
        elif config.mode == 'kv':
            stats = generate_kv_load(config)

        if stats:
            print_summary(config, stats)
            if stats.namespaces_failed > 0 or stats.leases_failed > 0 or stats.secrets_failed > 0:
                sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("Load generation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Load generation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
