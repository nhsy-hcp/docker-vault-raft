#!/usr/bin/env python3
"""
Vault Load Generation Script

Generates load on a Vault cluster by creating:
- Namespaces
- KV v2 engines per namespace
- Dummy secrets in each engine

Uses parallel workers to speed up operations.
"""

import argparse
import logging
import os
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Tuple
import random
import string

import hvac
from dotenv import load_dotenv


@dataclass
class LoadConfig:
    """Configuration for load generation"""
    namespaces: int
    engines_per_namespace: int
    secrets_per_engine: int
    workers: int
    vault_addr: str
    vault_token: str
    vault_cacert: str
    vault_skip_verify: bool
    parent_namespace: str = None


@dataclass
class LoadStats:
    """Statistics for load generation"""
    namespaces_created: int = 0
    namespaces_skipped: int = 0
    namespaces_failed: int = 0
    engines_created: int = 0
    engines_skipped: int = 0
    engines_failed: int = 0
    secrets_created: int = 0
    secrets_skipped: int = 0
    secrets_failed: int = 0
    start_time: float = 0
    end_time: float = 0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def total_operations(self) -> int:
        return (self.namespaces_created + self.engines_created +
                self.secrets_created)

    @property
    def operations_per_second(self) -> float:
        if self.duration > 0:
            return self.total_operations / self.duration
        return 0


def setup_logging(level: str = "INFO"):
    """Configure logging"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


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

    # Add some metadata
    data['generated_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
    data['description'] = f"Load test secret with {num_keys} keys"

    return data


def create_vault_client(config: LoadConfig, namespace: str = None) -> hvac.Client:
    """Create a Vault client"""
    client = hvac.Client(
        url=config.vault_addr,
        token=config.vault_token,
        verify=False if config.vault_skip_verify else config.vault_cacert,
        namespace=namespace
    )

    if not client.is_authenticated():
        raise Exception(f"Failed to authenticate to Vault")

    return client


def create_namespace(config: LoadConfig, namespace_name: str) -> Tuple[str, str]:
    """Create a namespace

    Returns:
        Tuple[str, str]: (status, full_path) where status is 'created', 'skipped', or 'failed'
    """
    logger = logging.getLogger(__name__)
    full_path = f"{config.parent_namespace}/{namespace_name}" if config.parent_namespace else namespace_name

    try:
        # If parent namespace is specified, create client in that context
        client = create_vault_client(config, namespace=config.parent_namespace)

        # Create namespace (will be child of parent if parent is set)
        client.sys.create_namespace(path=namespace_name)

        logger.info(f"Created namespace: {full_path}")
        return 'created', full_path

    except Exception as e:
        error_msg = str(e).lower()
        # Check if namespace already exists
        if 'already exists' in error_msg:
            logger.debug(f"Namespace already exists (skipped): {full_path}")
            return 'skipped', full_path
        else:
            logger.error(f"Failed to create namespace {full_path}: {e}")
            return 'failed', full_path


def create_kv_engine(config: LoadConfig, namespace: str, engine_name: str) -> Tuple[str, str, str]:
    """Create a KV v2 engine in a namespace

    Returns:
        Tuple[str, str, str]: (status, namespace, engine_name) where status is 'created', 'skipped', or 'failed'
    """
    logger = logging.getLogger(__name__)

    try:
        client = create_vault_client(config, namespace=namespace)

        # Enable KV v2 engine
        client.sys.enable_secrets_engine(
            backend_type='kv',
            path=engine_name,
            options={'version': '2'}
        )
        logger.info(f"Created KV v2 engine: {namespace}/{engine_name}")

        return 'created', namespace, engine_name

    except Exception as e:
        error_msg = str(e).lower()
        # Check if engine already exists
        if 'path is already in use' in error_msg or 'existing mount' in error_msg:
            logger.debug(f"KV engine already exists (skipped): {namespace}/{engine_name}")
            return 'skipped', namespace, engine_name
        else:
            logger.error(f"Failed to create engine {namespace}/{engine_name}: {e}")
            return 'failed', namespace, engine_name


def write_secret(config: LoadConfig, namespace: str, engine_name: str,
                secret_path: str) -> Tuple[str, str, str, str]:
    """Write a secret to a KV v2 engine

    Returns:
        Tuple[str, str, str, str]: (status, namespace, engine_name, secret_path)
                                   where status is 'created', 'skipped', or 'failed'
    """
    logger = logging.getLogger(__name__)

    try:
        client = create_vault_client(config, namespace=namespace)

        # Check if secret already exists
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
            # Secret doesn't exist, continue to create
            pass

        # Generate random secret data
        secret_data = generate_random_secret_data()

        # Write secret
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


def create_namespace_with_engines(config: LoadConfig, namespace_num: int,
                                  stats: LoadStats) -> LoadStats:
    """Create a namespace with all its engines and secrets"""
    logger = logging.getLogger(__name__)
    namespace_name = f"load-test-ns-{namespace_num}"

    # Create namespace
    status, full_namespace_path = create_namespace(config, namespace_name)
    if status == 'created':
        stats.namespaces_created += 1
    elif status == 'skipped':
        stats.namespaces_skipped += 1
    else:  # failed
        stats.namespaces_failed += 1
        return stats

    # Create engines in the namespace
    for engine_num in range(1, config.engines_per_namespace + 1):
        engine_name = f"kv-{engine_num}"

        status, _, _ = create_kv_engine(config, full_namespace_path, engine_name)
        if status == 'created':
            stats.engines_created += 1
        elif status == 'skipped':
            stats.engines_skipped += 1
        else:  # failed
            stats.engines_failed += 1
            continue

        # Write secrets to the engine
        for secret_num in range(1, config.secrets_per_engine + 1):
            secret_path = f"secret-{secret_num}"

            status, _, _, _ = write_secret(
                config, full_namespace_path, engine_name, secret_path
            )
            if status == 'created':
                stats.secrets_created += 1
            elif status == 'skipped':
                stats.secrets_skipped += 1
            else:  # failed
                stats.secrets_failed += 1

    logger.info(f"Completed namespace {namespace_name}: "
                f"{stats.engines_created + stats.engines_skipped} engines, "
                f"{stats.secrets_created + stats.secrets_skipped} secrets")

    return stats


def generate_load(config: LoadConfig) -> LoadStats:
    """Generate load on Vault cluster"""
    logger = logging.getLogger(__name__)
    stats = LoadStats()
    stats.start_time = time.time()

    logger.info(f"Starting load generation:")
    if config.parent_namespace:
        logger.info(f"  Parent namespace: {config.parent_namespace}")
    logger.info(f"  Namespaces: {config.namespaces}")
    logger.info(f"  Engines per namespace: {config.engines_per_namespace}")
    logger.info(f"  Secrets per engine: {config.secrets_per_engine}")
    logger.info(f"  Workers: {config.workers}")
    logger.info(f"  Total operations: {config.namespaces} namespaces, "
                f"{config.namespaces * config.engines_per_namespace} engines, "
                f"{config.namespaces * config.engines_per_namespace * config.secrets_per_engine} secrets")

    # Create namespaces in parallel using thread pool
    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        futures = []

        for ns_num in range(1, config.namespaces + 1):
            future = executor.submit(
                create_namespace_with_engines,
                config,
                ns_num,
                LoadStats()
            )
            futures.append(future)

        # Collect results
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

                completed += 1
                progress = (completed / config.namespaces) * 100
                logger.info(f"Progress: {completed}/{config.namespaces} "
                           f"namespaces ({progress:.1f}%)")

            except Exception as e:
                logger.error(f"Task failed: {e}")
                stats.namespaces_failed += 1

    stats.end_time = time.time()

    return stats


def print_summary(config: LoadConfig, stats: LoadStats):
    """Print summary statistics"""
    logger = logging.getLogger(__name__)

    logger.info("")
    logger.info("=" * 60)
    logger.info("LOAD GENERATION SUMMARY")
    logger.info("=" * 60)
    logger.info("")
    logger.info("Configuration:")
    if config.parent_namespace:
        logger.info(f"  Parent namespace: {config.parent_namespace}")
    logger.info(f"  Namespaces: {config.namespaces}")
    logger.info(f"  Engines per namespace: {config.engines_per_namespace}")
    logger.info(f"  Secrets per engine: {config.secrets_per_engine}")
    logger.info(f"  Workers: {config.workers}")
    logger.info("")
    logger.info("Results:")
    logger.info(f"  Namespaces created: {stats.namespaces_created}")
    logger.info(f"  Namespaces skipped: {stats.namespaces_skipped}")
    logger.info(f"  Namespaces failed: {stats.namespaces_failed}")
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
    logger.info("")
    logger.info("=" * 60)


def main():
    """Main entry point"""
    # Load environment variables
    load_dotenv()

    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Generate load on Vault cluster',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--namespaces',
        type=int,
        default=5,
        help='Nubmer of namespaces to create'
    )
    parser.add_argument(
        '--engines',
        type=int,
        default=3,
        help='Number of KV v2 engines per namespace'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help='Number of parallel workers/threads'
    )
    parser.add_argument(
        '--secrets-per-engine',
        type=int,
        default=10,
        help='Number of secrets to create per engine'
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
    config = LoadConfig(
        namespaces=args.namespaces,
        engines_per_namespace=args.engines,
        secrets_per_engine=args.secrets_per_engine,
        workers=args.workers,
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

    # Generate load
    try:
        stats = generate_load(config)
        print_summary(config, stats)

        # Exit with error if there were failures
        if (stats.namespaces_failed > 0 or stats.engines_failed > 0 or
            stats.secrets_failed > 0):
            sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("Load generation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Load generation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()