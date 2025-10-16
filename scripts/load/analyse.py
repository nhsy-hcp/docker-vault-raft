#!/usr/bin/env python3
"""
Vault Snapshot Analysis Script

Analyzes Vault Raft snapshot JSON files for operational insights including:
- Size distribution by path
- Key count distribution by path
- Anomaly detection (threshold-based)
- Recommendations for optimization

Assumes JSON files are generated using:
    vault operator raft snapshot inspect -format=json <snapshot.snap> > <snapshot.json>
"""

import argparse
import json
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Tuple, Optional


# --- Dataclasses ---

@dataclass
class Config:
    """Configuration for snapshot analysis"""
    json_file: Path
    size_threshold: int = 1048576  # 1MB
    key_threshold: int = 1000
    large_entry_threshold: int = 102400  # 100KB
    top_n: int = 10
    format: str = 'text'
    output: Optional[Path] = None


@dataclass
class PathMetrics:
    """Metrics for a specific path in the snapshot"""
    path: str
    total_size: int
    key_count: int
    avg_entry_size: float
    max_entry_size: int
    size_percentage: float = 0.0

    @property
    def size_per_key(self) -> float:
        """Average size per key"""
        if self.key_count > 0:
            return self.total_size / self.key_count
        return 0.0


@dataclass
class AnomalyReport:
    """Report of detected anomaly"""
    type: str  # size_threshold, key_threshold, large_entry, empty_path, deep_nesting
    path: str
    value: float
    threshold: float
    severity: str  # info, warning, critical
    recommendation: str

    @property
    def multiplier(self) -> float:
        """How many times the threshold was exceeded"""
        if self.threshold > 0:
            return self.value / self.threshold
        return 0.0


@dataclass
class SnapshotStats:
    """Overall statistics for a snapshot"""
    snapshot_name: str
    total_size: int
    total_entries: int
    raft_index: int
    raft_term: int
    timestamp: str
    path_metrics: List[PathMetrics] = field(default_factory=list)

    @property
    def avg_entry_size(self) -> float:
        """Average entry size across all entries"""
        if self.total_entries > 0:
            return self.total_size / self.total_entries
        return 0.0


# --- Utility Functions ---

def setup_logging(level: str = "INFO"):
    """Configure logging"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def format_bytes(bytes_val: int) -> str:
    """Convert bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"


def format_number(num: int) -> str:
    """Format number with thousand separators"""
    return f"{num:,}"


# --- JSON Parsing ---

def load_snapshot_json(json_file: Path) -> Dict:
    """Load and validate snapshot JSON file"""
    logger = logging.getLogger(__name__)

    if not json_file.exists():
        logger.error(f"JSON file not found: {json_file}")
        raise FileNotFoundError(f"JSON file not found: {json_file}")

    if not json_file.is_file():
        logger.error(f"Path is not a file: {json_file}")
        raise ValueError(f"Path is not a file: {json_file}")

    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        logger.info(f"Loaded JSON file: {json_file}")
        return data
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON file: {e}")
        raise ValueError(f"Invalid JSON format: {e}")
    except Exception as e:
        logger.error(f"Failed to read JSON file: {e}")
        raise


def extract_path_prefix(key: str, depth: int = 3) -> str:
    """
    Extract path prefix from a key.

    For example:
      - "logical/abc123/core/mounts" -> "logical/abc123/core"
      - "sys/token/id/h123" -> "sys/token/id"
    """
    parts = key.split('/')
    prefix_parts = parts[:min(depth, len(parts))]
    return '/'.join(prefix_parts) if prefix_parts else key


def get_path_depth(path: str) -> int:
    """Get the depth of a path (number of levels)"""
    return len(path.split('/'))


# --- Analysis Functions ---

def analyze_paths(data: Dict, config: Config) -> Tuple[Dict[str, PathMetrics], int, int]:
    """
    Analyze paths from snapshot data.

    Returns:
        - Dictionary of path metrics
        - Total size across all entries
        - Total number of entries
    """
    logger = logging.getLogger(__name__)

    # Extract KV entries from snapshot
    kv_data = data.get('data', {})
    if not kv_data:
        logger.warning("No 'data' field found in snapshot JSON")
        return {}, 0, 0

    # Aggregate metrics by path prefix
    path_data = defaultdict(lambda: {'total_size': 0, 'key_count': 0, 'max_entry_size': 0, 'entries': []})
    total_size = 0
    total_entries = 0

    # Iterate through all KV pairs
    for key, value in kv_data.items():
        # Calculate entry size (key + value)
        # In Vault snapshots, the value is typically a base64-encoded string
        key_size = len(key.encode('utf-8'))
        value_size = len(str(value).encode('utf-8')) if value else 0
        entry_size = key_size + value_size

        # Extract path prefix
        path = extract_path_prefix(key)

        # Update metrics
        path_data[path]['total_size'] += entry_size
        path_data[path]['key_count'] += 1
        path_data[path]['max_entry_size'] = max(path_data[path]['max_entry_size'], entry_size)
        path_data[path]['entries'].append(entry_size)

        total_size += entry_size
        total_entries += 1

    logger.info(f"Analyzed {total_entries} entries across {len(path_data)} unique paths")

    # Convert to PathMetrics objects
    path_metrics = {}
    for path, metrics in path_data.items():
        avg_size = metrics['total_size'] / metrics['key_count'] if metrics['key_count'] > 0 else 0
        size_pct = (metrics['total_size'] / total_size * 100) if total_size > 0 else 0

        path_metrics[path] = PathMetrics(
            path=path,
            total_size=metrics['total_size'],
            key_count=metrics['key_count'],
            avg_entry_size=avg_size,
            max_entry_size=metrics['max_entry_size'],
            size_percentage=size_pct
        )

    return path_metrics, total_size, total_entries


def analyze_size_distribution(path_metrics: Dict[str, PathMetrics], top_n: int) -> List[PathMetrics]:
    """
    Analyze size distribution across paths.

    Returns sorted list of top N paths by size.
    """
    sorted_paths = sorted(path_metrics.values(), key=lambda p: p.total_size, reverse=True)
    return sorted_paths[:top_n]


def analyze_key_distribution(path_metrics: Dict[str, PathMetrics], top_n: int) -> List[PathMetrics]:
    """
    Analyze key count distribution across paths.

    Returns sorted list of top N paths by key count.
    """
    sorted_paths = sorted(path_metrics.values(), key=lambda p: p.key_count, reverse=True)
    return sorted_paths[:top_n]


def detect_anomalies(path_metrics: Dict[str, PathMetrics], config: Config) -> List[AnomalyReport]:
    """
    Detect anomalies in snapshot data based on thresholds.

    Checks for:
    - Paths exceeding size threshold
    - Paths exceeding key count threshold
    - Paths with large individual entries
    - Deep path nesting
    """
    logger = logging.getLogger(__name__)
    anomalies = []

    for path, metrics in path_metrics.items():
        # Check size threshold
        if metrics.total_size > config.size_threshold:
            severity = 'critical' if metrics.total_size > config.size_threshold * 5 else 'warning'
            anomalies.append(AnomalyReport(
                type='size_threshold',
                path=path,
                value=metrics.total_size,
                threshold=config.size_threshold,
                severity=severity,
                recommendation=f"Path exceeds size threshold. Consider:\n"
                              f"  - Reviewing data retention policies\n"
                              f"  - Implementing cleanup policies\n"
                              f"  - Archiving old data"
            ))

        # Check key count threshold
        if metrics.key_count > config.key_threshold:
            severity = 'critical' if metrics.key_count > config.key_threshold * 3 else 'warning'
            anomalies.append(AnomalyReport(
                type='key_threshold',
                path=path,
                value=metrics.key_count,
                threshold=config.key_threshold,
                severity=severity,
                recommendation=f"High key count may impact Raft performance. Consider:\n"
                              f"  - Partitioning data across multiple paths\n"
                              f"  - Reviewing data structure\n"
                              f"  - Implementing data lifecycle policies"
            ))

        # Check large entry threshold
        if metrics.max_entry_size > config.large_entry_threshold:
            severity = 'warning' if metrics.max_entry_size < config.large_entry_threshold * 5 else 'critical'
            anomalies.append(AnomalyReport(
                type='large_entry',
                path=path,
                value=metrics.max_entry_size,
                threshold=config.large_entry_threshold,
                severity=severity,
                recommendation=f"Large entries impact Raft replication. Consider:\n"
                              f"  - Splitting large entries into smaller chunks\n"
                              f"  - Using external storage for large data\n"
                              f"  - Reviewing data serialization format"
            ))

        # Check deep nesting
        depth = get_path_depth(path)
        if depth > 5:
            anomalies.append(AnomalyReport(
                type='deep_nesting',
                path=path,
                value=depth,
                threshold=5,
                severity='info',
                recommendation=f"Deep path nesting may impact traversal performance. Consider:\n"
                              f"  - Flattening path hierarchy\n"
                              f"  - Reviewing namespace structure"
            ))

    # Sort anomalies by severity
    severity_order = {'critical': 0, 'warning': 1, 'info': 2}
    anomalies.sort(key=lambda a: (severity_order.get(a.severity, 3), -a.value))

    logger.info(f"Detected {len(anomalies)} anomalies "
                f"(critical: {sum(1 for a in anomalies if a.severity == 'critical')}, "
                f"warning: {sum(1 for a in anomalies if a.severity == 'warning')}, "
                f"info: {sum(1 for a in anomalies if a.severity == 'info')})")

    return anomalies


# --- Output Formatting ---

def print_text_summary(stats: SnapshotStats, top_by_size: List[PathMetrics],
                       top_by_keys: List[PathMetrics], anomalies: List[AnomalyReport],
                       config: Config):
    """Print text summary of snapshot analysis"""
    output = []

    # Header
    output.append("")
    output.append("=" * 80)
    output.append("VAULT SNAPSHOT ANALYSIS")
    output.append("=" * 80)
    output.append("")

    # Snapshot information
    output.append("Snapshot Information:")
    output.append(f"  File: {stats.snapshot_name}")
    output.append(f"  Total Size: {format_bytes(stats.total_size)}")
    output.append(f"  Total Entries: {format_number(stats.total_entries)}")
    output.append(f"  Average Entry Size: {format_bytes(int(stats.avg_entry_size))}")
    output.append(f"  Raft Index: {stats.raft_index}")
    output.append(f"  Raft Term: {stats.raft_term}")
    if stats.timestamp:
        output.append(f"  Timestamp: {stats.timestamp}")
    output.append(f"  Total Unique Paths: {len(stats.path_metrics)}")
    output.append("")

    # Size distribution
    output.append("Size Distribution:")
    output.append(f"  Top {len(top_by_size)} Paths by Size:")
    output.append("")
    output.append(f"  {'Rank':<6} {'Path':<40} {'Size':<10} {'%':<7} {'Keys':<8} {'Avg Size':<10}")
    output.append("  " + "-" * 80)

    for i, pm in enumerate(top_by_size, 1):
        output.append(f"  {i:<6} {pm.path[:40]:<40} {format_bytes(pm.total_size):<10} "
                     f"{pm.size_percentage:>6.1f}% {pm.key_count:<8} {format_bytes(int(pm.avg_entry_size)):<10}")
    output.append("")

    # Key distribution
    output.append("Key Distribution:")
    output.append(f"  Top {len(top_by_keys)} Paths by Key Count:")
    output.append("")
    output.append(f"  {'Rank':<6} {'Path':<40} {'Keys':<8} {'Size':<10} {'Avg Size':<10}")
    output.append("  " + "-" * 80)

    for i, pm in enumerate(top_by_keys, 1):
        output.append(f"  {i:<6} {pm.path[:40]:<40} {pm.key_count:<8} "
                     f"{format_bytes(pm.total_size):<10} {format_bytes(int(pm.avg_entry_size)):<10}")
    output.append("")

    # Anomalies
    if anomalies:
        output.append(f"Anomalies Detected ({len(anomalies)} total):")
        output.append("")

        critical_anomalies = [a for a in anomalies if a.severity == 'critical']
        warning_anomalies = [a for a in anomalies if a.severity == 'warning']
        info_anomalies = [a for a in anomalies if a.severity == 'info']

        for anomaly_list, severity_label in [
            (critical_anomalies, 'CRITICAL'),
            (warning_anomalies, 'WARNING'),
            (info_anomalies, 'INFO')
        ]:
            for anomaly in anomaly_list:
                output.append(f"  [{severity_label}] {anomaly.type.replace('_', ' ').title()}")
                output.append(f"    Path: {anomaly.path}")

                if anomaly.type == 'size_threshold':
                    output.append(f"    Size: {format_bytes(int(anomaly.value))} "
                                f"(threshold: {format_bytes(int(anomaly.threshold))}, "
                                f"{anomaly.multiplier:.1f}x over)")
                elif anomaly.type == 'key_threshold':
                    output.append(f"    Keys: {format_number(int(anomaly.value))} "
                                f"(threshold: {format_number(int(anomaly.threshold))}, "
                                f"{anomaly.multiplier:.1f}x over)")
                elif anomaly.type == 'large_entry':
                    output.append(f"    Max Entry Size: {format_bytes(int(anomaly.value))} "
                                f"(threshold: {format_bytes(int(anomaly.threshold))}, "
                                f"{anomaly.multiplier:.1f}x over)")
                elif anomaly.type == 'deep_nesting':
                    output.append(f"    Depth: {int(anomaly.value)} levels "
                                f"(threshold: {int(anomaly.threshold)} levels)")

                output.append(f"    Recommendation: {anomaly.recommendation}")
                output.append("")
    else:
        output.append("No anomalies detected.")
        output.append("")

    # Summary
    output.append("Summary:")
    output.append(f"  Total Paths Analyzed: {len(stats.path_metrics)}")
    if anomalies:
        unique_paths_with_anomalies = len(set(a.path for a in anomalies))
        output.append(f"  Paths with Anomalies: {unique_paths_with_anomalies} "
                     f"({unique_paths_with_anomalies / len(stats.path_metrics) * 100:.1f}%)")
        output.append(f"  Critical Issues: {len(critical_anomalies)}")
        output.append(f"  Warnings: {len(warning_anomalies)}")
        output.append(f"  Info: {len(info_anomalies)}")
    output.append("")

    # Recommendations
    if anomalies:
        output.append("Top Recommendations:")
        critical_paths = set(a.path for a in critical_anomalies)
        for i, path in enumerate(list(critical_paths)[:5], 1):
            path_anomalies = [a for a in critical_anomalies if a.path == path]
            path_metrics = next((pm for pm in stats.path_metrics if pm.path == path), None)
            if path_metrics:
                output.append(f"  {i}. Address critical issues in {path} "
                            f"({format_bytes(path_metrics.total_size)}, "
                            f"{format_number(path_metrics.key_count)} keys)")
        output.append("")

    output.append("=" * 80)
    output.append("")

    # Output to file or stdout
    text = '\n'.join(output)
    if config.output:
        with open(config.output, 'w') as f:
            f.write(text)
        logging.getLogger(__name__).info(f"Analysis saved to: {config.output}")
    else:
        print(text)


# --- Main ---

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='''
Analyze Vault Raft snapshot JSON files for operational insights.

This script provides detailed analysis of Vault snapshots including:
  - Size distribution by path
  - Key count distribution by path
  - Anomaly detection (thresholds for size, key count, entry size)
  - Recommendations for optimization

Prerequisites:
  Generate JSON snapshot using:
    vault operator raft snapshot inspect -format=json <snapshot.snap> > <snapshot.json>

Examples:
  # Basic analysis
  python3 analyse.py --json backup-20251016-1442.json

  # With custom thresholds
  python3 analyse.py --json backup-20251016-1442.json --size-threshold 5000000 --key-threshold 2000

  # Save output to file
  python3 analyse.py --json backup-20251016-1442.json --output analysis-report.txt

  # Via Taskfile
  task snapshot:analyze -- --json snapshots/backup-20251016-1442.json
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--json',
                       type=Path,
                       required=True,
                       help='path to snapshot JSON file (required)')
    parser.add_argument('--size-threshold',
                       type=int,
                       default=1048576,
                       help='anomaly threshold for path size in bytes (default: 1048576 = 1MB)')
    parser.add_argument('--key-threshold',
                       type=int,
                       default=1000,
                       help='anomaly threshold for key count (default: 1000)')
    parser.add_argument('--entry-threshold',
                       type=int,
                       default=102400,
                       help='anomaly threshold for single entry size in bytes (default: 102400 = 100KB)')
    parser.add_argument('--top-n',
                       type=int,
                       default=10,
                       help='number of top paths to show (default: 10)')
    parser.add_argument('--format',
                       choices=['text', 'json', 'md'],
                       default='text',
                       help='output format (default: text) - only text supported in initial version')
    parser.add_argument('--output',
                       type=Path,
                       help='save output to file instead of stdout')
    parser.add_argument('--log-level',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO',
                       help='logging level (default: INFO)')

    args = parser.parse_args()

    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    # Create config
    config = Config(
        json_file=args.json,
        size_threshold=args.size_threshold,
        key_threshold=args.key_threshold,
        large_entry_threshold=args.entry_threshold,
        top_n=args.top_n,
        format=args.format,
        output=args.output
    )

    try:
        # Load snapshot JSON
        logger.info(f"Loading snapshot JSON: {config.json_file}")
        data = load_snapshot_json(config.json_file)

        # Extract metadata
        meta = data.get('meta', {})
        raft_index = meta.get('index', 0)
        raft_term = meta.get('term', 0)
        timestamp = meta.get('timestamp', '')

        # Analyze paths
        logger.info("Analyzing paths...")
        path_metrics, total_size, total_entries = analyze_paths(data, config)

        # Create snapshot stats
        stats = SnapshotStats(
            snapshot_name=config.json_file.name,
            total_size=total_size,
            total_entries=total_entries,
            raft_index=raft_index,
            raft_term=raft_term,
            timestamp=timestamp,
            path_metrics=list(path_metrics.values())
        )

        # Analyze distributions
        logger.info("Analyzing size distribution...")
        top_by_size = analyze_size_distribution(path_metrics, config.top_n)

        logger.info("Analyzing key distribution...")
        top_by_keys = analyze_key_distribution(path_metrics, config.top_n)

        # Detect anomalies
        logger.info("Detecting anomalies...")
        anomalies = detect_anomalies(path_metrics, config)

        # Output results
        if config.format == 'text':
            print_text_summary(stats, top_by_size, top_by_keys, anomalies, config)
        else:
            logger.error(f"Output format '{config.format}' not yet implemented. Using text format.")
            print_text_summary(stats, top_by_size, top_by_keys, anomalies, config)

        # Exit with error if critical anomalies found
        critical_count = sum(1 for a in anomalies if a.severity == 'critical')
        if critical_count > 0:
            logger.warning(f"Analysis completed with {critical_count} critical issues")
            sys.exit(1)
        else:
            logger.info("Analysis completed successfully")
            sys.exit(0)

    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
