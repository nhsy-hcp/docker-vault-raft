#!/usr/bin/env python3
"""
Vault Lease Generation Script

Generates Vault leases by creating dynamic secrets using PKI certificates.
Each certificate issued creates a lease that can be tracked, renewed, and revoked.

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


@dataclass
class LeaseConfig:
    """Configuration for lease generation"""
    namespaces: int
    leases_per_namespace: int
    workers: int
    ttl: str
    vault_addr: str
    vault_token: str
    vault_cacert: str
    vault_skip_verify: bool
    parent_namespace: Optional[str] = None
    pki_path: str = "pki"


@dataclass
class LeaseStats:
    """Statistics for lease generation"""
    namespaces_processed: int = 0
    namespaces_failed: int = 0
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
    start_time: float = 0
    end_time: float = 0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def total_operations(self) -> int:
        return (self.pki_engines_created + self.cas_configured +
                self.roles_configured + self.leases_created)

    @property
    def operations_per_second(self) -> float:
        if self.duration > 0:
            return self.total_operations / self.duration
        return 0

    @property
    def leases_per_second(self) -> float:
        if self.duration > 0:
            return self.leases_created / self.duration
        return 0


def setup_logging(level: str = "INFO"):
    """Configure logging"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def create_vault_client(config: LeaseConfig, namespace: str = None) -> hvac.Client:
    """Create a Vault client"""
    # For child namespaces, we need to set the namespace on the client
    # but use the root token (which has access across namespaces)
    # The namespace parameter should be just the parent namespace path
    # and the child operations will be relative to that

    # If a parent namespace is configured and we're working with a child namespace,
    # we need to handle the namespace hierarchy properly
    if namespace and config.parent_namespace:
        # For child namespaces under a parent, use only the parent namespace
        # The child namespace operations will be done via API paths
        actual_namespace = config.parent_namespace
    elif namespace:
        # Use the provided namespace
        actual_namespace = namespace
    else:
        # No namespace (root level)
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


def create_namespace(config: LeaseConfig, namespace_path: str) -> Tuple[str, str]:
    """Create a namespace in Vault

    Returns:
        Tuple[str, str]: (status, namespace) where status is 'created', 'skipped', or 'failed'
    """
    logger = logging.getLogger(__name__)

    try:
        # For nested namespaces, we need to use the parent namespace client
        # and create the child namespace via API
        if config.parent_namespace and '/' in namespace_path:
            # Extract parent and child parts
            parts = namespace_path.split('/')
            parent_ns = '/'.join(parts[:-1])
            child_ns = parts[-1]

            # Create client with parent namespace
            client = create_vault_client(config, namespace=parent_ns)
        else:
            # Root level namespace creation
            client = create_vault_client(config)
            child_ns = namespace_path

        # Create namespace
        client.sys.create_namespace(path=child_ns)
        logger.info(f"Created namespace: {namespace_path}")
        return 'created', namespace_path

    except Exception as e:
        error_msg = str(e).lower()
        # Check if namespace already exists
        if 'namespace already exists' in error_msg or 'existing namespace' in error_msg:
            logger.debug(f"Namespace already exists (skipped): {namespace_path}")
            return 'skipped', namespace_path
        else:
            logger.error(f"Failed to create namespace {namespace_path}: {e}")
            return 'failed', namespace_path


def enable_pki_engine(config: LeaseConfig, namespace: str) -> Tuple[str, str]:
    """Enable PKI secrets engine in a namespace

    Returns:
        Tuple[str, str]: (status, namespace) where status is 'created', 'skipped', or 'failed'
    """
    logger = logging.getLogger(__name__)

    try:
        client = create_vault_client(config, namespace=namespace)

        # Enable PKI engine
        client.sys.enable_secrets_engine(
            backend_type='pki',
            path=config.pki_path,
            config={'max_lease_ttl': '87600h'}  # 10 years
        )
        logger.info(f"Enabled PKI engine: {namespace}/{config.pki_path}")
        return 'created', namespace

    except Exception as e:
        error_msg = str(e).lower()
        # Check if engine already exists
        if 'path is already in use' in error_msg or 'existing mount' in error_msg:
            logger.debug(f"PKI engine already exists (skipped): {namespace}/{config.pki_path}")
            return 'skipped', namespace
        else:
            logger.error(f"Failed to enable PKI engine {namespace}/{config.pki_path}: {e}")
            return 'failed', namespace


def configure_pki_ca(config: LeaseConfig, namespace: str) -> Tuple[str, str]:
    """Configure PKI CA in a namespace

    Returns:
        Tuple[str, str]: (status, namespace) where status is 'configured', 'skipped', or 'failed'
    """
    logger = logging.getLogger(__name__)

    try:
        client = create_vault_client(config, namespace=namespace)

        # Check if CA already exists
        try:
            ca_cert = client.secrets.pki.read_ca_certificate(mount_point=config.pki_path)
            if ca_cert:
                logger.debug(f"PKI CA already configured (skipped): {namespace}/{config.pki_path}")
                return 'skipped', namespace
        except:
            # CA doesn't exist, continue to configure
            pass

        # Generate root CA
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


def configure_pki_role(config: LeaseConfig, namespace: str, role_name: str = 'loadtest') -> Tuple[str, str]:
    """Configure PKI role for certificate issuance

    Returns:
        Tuple[str, str]: (status, namespace) where status is 'configured' or 'failed'
    """
    logger = logging.getLogger(__name__)

    try:
        client = create_vault_client(config, namespace=namespace)

        # Create role
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
    """Generate a CSR and private key using OpenSSL-like approach

    Returns:
        Tuple[str, str]: (csr_pem, private_key_pem)
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(private_key, hashes.SHA256())

    # Serialize to PEM
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    return csr_pem, private_key_pem


def sign_certificate(config: LeaseConfig, namespace: str, cert_num: int,
                     role_name: str = 'loadtest', max_retries: int = 3) -> Tuple[str, Optional[str], str]:
    """Sign a certificate using CSR to generate a lease (faster than issue)

    Returns:
        Tuple[str, Optional[str], str]: (status, lease_id, namespace)
                                       where status is 'created' or 'failed'
    """
    logger = logging.getLogger(__name__)

    # Generate random common name once
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    common_name = f"cert-{cert_num}-{random_suffix}.loadtest.local"

    for attempt in range(max_retries):
        try:
            # Generate CSR
            csr_pem, _ = generate_csr(common_name)

            client = create_vault_client(config, namespace=namespace)

            # Sign certificate using CSR (faster than issue)
            result = client.secrets.pki.sign_certificate(
                name=role_name,
                csr=csr_pem,
                common_name=common_name,
                mount_point=config.pki_path,
                extra_params={
                    'ttl': config.ttl
                }
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
            # Check if this is an "unknown role" error (race condition)
            if 'unknown role' in error_msg and attempt < max_retries - 1:
                # Exponential backoff: 1s, 2s, 4s
                sleep_time = 1 * (2 ** attempt)
                logger.debug(f"Role not ready yet for {namespace}/{config.pki_path}, "
                           f"retrying in {sleep_time}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(sleep_time)
                continue
            else:
                # Not a retryable error or max retries reached
                logger.error(f"Failed to sign certificate {namespace}/{config.pki_path}: {e}")
                return 'failed', None, namespace

    # Should not reach here, but just in case
    logger.error(f"Failed to sign certificate {namespace}/{config.pki_path} after {max_retries} attempts")
    return 'failed', None, namespace


def setup_namespace_pki(config: LeaseConfig, namespace: str) -> Tuple[str, str]:
    """Setup PKI engine in a namespace

    Returns:
        Tuple[str, str]: (status, namespace) where status is 'success' or 'failed'
    """
    logger = logging.getLogger(__name__)

    # Enable PKI engine
    status, _ = enable_pki_engine(config, namespace)
    if status == 'failed':
        return 'failed', namespace

    # Configure CA
    status, _ = configure_pki_ca(config, namespace)
    if status == 'failed':
        return 'failed', namespace

    # Configure role
    status, _ = configure_pki_role(config, namespace)
    if status == 'failed':
        return 'failed', namespace

    logger.info(f"PKI setup complete: {namespace}/{config.pki_path}")
    return 'success', namespace


def generate_leases_for_namespace(config: LeaseConfig, namespace_num: int,
                                  stats: LeaseStats) -> LeaseStats:
    """Generate leases for a single namespace"""
    logger = logging.getLogger(__name__)

    # Build namespace path
    if config.parent_namespace:
        namespace_name = f"load-test-ns-{namespace_num}"
        full_namespace_path = f"{config.parent_namespace}/{namespace_name}"
    else:
        namespace_name = f"load-test-ns-{namespace_num}"
        full_namespace_path = namespace_name

    # Create namespace first
    ns_status, _ = create_namespace(config, full_namespace_path)
    if ns_status == 'failed':
        stats.namespaces_failed += 1
        return stats

    # Setup PKI engine
    pki_status, _ = enable_pki_engine(config, full_namespace_path)
    if pki_status == 'created':
        stats.pki_engines_created += 1
    elif pki_status == 'skipped':
        stats.pki_engines_skipped += 1
    else:  # failed
        stats.pki_engines_failed += 1
        stats.namespaces_failed += 1
        return stats

    # Configure CA
    ca_status, _ = configure_pki_ca(config, full_namespace_path)
    if ca_status == 'configured':
        stats.cas_configured += 1
    elif ca_status == 'skipped':
        pass  # Already configured
    else:  # failed
        stats.cas_failed += 1
        stats.namespaces_failed += 1
        return stats

    # Configure role
    role_status, _ = configure_pki_role(config, full_namespace_path)
    if role_status == 'configured':
        stats.roles_configured += 1
        # Brief delay to ensure role is fully committed before issuing certificates
        time.sleep(0.1)
    else:  # failed
        stats.roles_failed += 1
        stats.namespaces_failed += 1
        return stats

    # Issue certificates to generate leases
    for cert_num in range(1, config.leases_per_namespace + 1):
        cert_status, lease_id, _ = issue_certificate(
            config, full_namespace_path, cert_num
        )
        if cert_status == 'created':
            stats.leases_created += 1
            if lease_id:
                stats.lease_ids.append(lease_id)
        else:  # failed
            stats.leases_failed += 1

    stats.namespaces_processed += 1
    logger.info(f"Completed namespace {namespace_name}: "
                f"{stats.leases_created} leases created")

    return stats


def generate_all_leases(config: LeaseConfig) -> LeaseStats:
    """Generate leases across all namespaces"""
    logger = logging.getLogger(__name__)
    stats = LeaseStats()
    stats.start_time = time.time()

    logger.info(f"Starting lease generation:")
    if config.parent_namespace:
        logger.info(f"  Parent namespace: {config.parent_namespace}")
    logger.info(f"  Namespaces: {config.namespaces}")
    logger.info(f"  Leases per namespace: {config.leases_per_namespace}")
    logger.info(f"  Lease TTL: {config.ttl}")
    logger.info(f"  Workers: {config.workers}")
    logger.info(f"  Total leases to generate: {config.namespaces * config.leases_per_namespace}")

    # Create namespaces and generate leases in parallel
    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        futures = []

        for ns_num in range(1, config.namespaces + 1):
            future = executor.submit(
                generate_leases_for_namespace,
                config,
                ns_num,
                LeaseStats()
            )
            futures.append(future)

        # Collect results
        completed = 0
        for future in as_completed(futures):
            try:
                ns_stats = future.result()
                stats.namespaces_processed += ns_stats.namespaces_processed
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


def print_summary(config: LeaseConfig, stats: LeaseStats):
    """Print summary statistics"""
    logger = logging.getLogger(__name__)

    logger.info("")
    logger.info("=" * 60)
    logger.info("LEASE GENERATION SUMMARY")
    logger.info("=" * 60)
    logger.info("")
    logger.info("Configuration:")
    if config.parent_namespace:
        logger.info(f"  Parent namespace: {config.parent_namespace}")
    logger.info(f"  Namespaces: {config.namespaces}")
    logger.info(f"  Leases per namespace: {config.leases_per_namespace}")
    logger.info(f"  Lease TTL: {config.ttl}")
    logger.info(f"  Workers: {config.workers}")
    logger.info("")
    logger.info("Results:")
    logger.info(f"  Namespaces processed: {stats.namespaces_processed}")
    logger.info(f"  Namespaces failed: {stats.namespaces_failed}")
    logger.info(f"  PKI engines created: {stats.pki_engines_created}")
    logger.info(f"  PKI engines skipped: {stats.pki_engines_skipped}")
    logger.info(f"  PKI engines failed: {stats.pki_engines_failed}")
    logger.info(f"  CAs configured: {stats.cas_configured}")
    logger.info(f"  CAs failed: {stats.cas_failed}")
    logger.info(f"  Roles configured: {stats.roles_configured}")
    logger.info(f"  Roles failed: {stats.roles_failed}")
    logger.info(f"  Leases created: {stats.leases_created}")
    logger.info(f"  Leases failed: {stats.leases_failed}")
    logger.info("")
    logger.info("Performance:")
    logger.info(f"  Duration: {stats.duration:.2f} seconds")
    logger.info(f"  Operations per second: {stats.operations_per_second:.2f}")
    logger.info(f"  Leases per second: {stats.leases_per_second:.2f}")
    logger.info("")
    logger.info("=" * 60)


def main():
    """Main entry point"""
    # Load environment variables
    load_dotenv()

    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Generate Vault leases using PKI certificates',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--namespaces',
        type=int,
        default=5,
        help='Number of namespaces to use'
    )
    parser.add_argument(
        '--leases-per-namespace',
        type=int,
        default=10,
        help='Number of leases (certificates) to generate per namespace'
    )
    parser.add_argument(
        '--ttl',
        default='1h',
        help='Lease TTL (e.g., 1h, 30m, 24h)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help='Number of parallel workers/threads'
    )
    parser.add_argument(
        '--pki-path',
        default='pki',
        help='PKI secrets engine mount path'
    )
    parser.add_argument(
        '--vault-addr',
        default=os.getenv('VAULT_ADDR', 'https://localhost:8200'),
        help='Vault address'
    )
    parser.add_argument(
        '--vault-token',
        default=os.getenv('VAULT_TOKEN'),
        help='Vault token'
    )
    parser.add_argument(
        '--vault-cacert',
        default=os.getenv('VAULT_CACERT'),
        help='Path to CA certificate'
    )
    parser.add_argument(
        '--vault-skip-verify',
        action='store_true',
        default=os.getenv('VAULT_SKIP_VERIFY', 'false').lower() == 'true',
        help='Skip TLS verification'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    parser.add_argument(
        '--parent-namespace',
        default=os.getenv('VAULT_NAMESPACE', 'loadtest'),
        help='Parent namespace to create child namespaces under'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    # Suppress InsecureRequestWarning when skip verify is enabled
    if args.vault_skip_verify:
        warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    # Validate token
    if not args.vault_token:
        logger.error("Vault token not provided. Set VAULT_TOKEN environment variable "
                    "or use --vault-token")
        sys.exit(1)

    # Create configuration
    config = LeaseConfig(
        namespaces=args.namespaces,
        leases_per_namespace=args.leases_per_namespace,
        ttl=args.ttl,
        workers=args.workers,
        pki_path=args.pki_path,
        vault_addr=args.vault_addr,
        vault_token=args.vault_token,
        vault_cacert=args.vault_cacert,
        vault_skip_verify=args.vault_skip_verify,
        parent_namespace=args.parent_namespace
    )

    # Test Vault connection
    try:
        logger.info(f"Testing connection to Vault at {config.vault_addr}...")
        client = create_vault_client(config)
        logger.info("Successfully connected to Vault")
    except Exception as e:
        logger.error(f"Failed to connect to Vault: {e}")
        sys.exit(1)

    # Generate leases
    try:
        stats = generate_all_leases(config)
        print_summary(config, stats)

        # Exit with error if there were failures
        if stats.namespaces_failed > 0 or stats.leases_failed > 0:
            sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("Lease generation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Lease generation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
