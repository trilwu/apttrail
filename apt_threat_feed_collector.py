#!/usr/bin/env python3
"""
APTtrail - APT Threat Feed Collector
Automatically collects and processes APT threat indicators from Maltrail repository
Based on Maltrail project (https://github.com/stamparm/maltrail)
"""

import os
import re
import json
import csv
import argparse
import subprocess
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict
import ipaddress
import urllib.parse


class APTThreatFeedCollector:
    def __init__(self, maltrail_path: str = "data/maltrail", auto_update: bool = True):
        """
        Initialize the APT Threat Feed Collector

        Args:
            maltrail_path: Path to the local Maltrail repository
            auto_update: Whether to auto-update the repository
        """
        self.maltrail_path = Path(maltrail_path)
        self.apt_files_path = self.maltrail_path / "trails" / "static" / "malware"
        self.auto_update = auto_update
        self.indicators = defaultdict(lambda: defaultdict(set))
        self.metadata = defaultdict(dict)

    def update_repository(self) -> bool:
        """Update the Maltrail repository via git pull"""
        if not self.auto_update:
            return False

        try:
            if not (self.maltrail_path / ".git").exists():
                print(f"Cloning Maltrail repository to {self.maltrail_path}...")
                subprocess.run(
                    ["git", "clone", "https://github.com/stamparm/maltrail.git", str(self.maltrail_path)],
                    check=True, capture_output=True
                )
                print("Repository cloned successfully")
            else:
                print(f"Updating Maltrail repository at {self.maltrail_path}...")
                subprocess.run(
                    ["git", "pull"],
                    cwd=self.maltrail_path,
                    check=True, capture_output=True
                )
                print("Repository updated successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error updating repository: {e}")
            return False

    def classify_indicator(self, indicator: str) -> str:
        """
        Classify an indicator by type

        Returns: One of 'ipv4', 'ipv6', 'domain', 'url', 'file_path', 'hash', 'unknown'
        """
        indicator = indicator.strip()

        # Skip empty lines
        if not indicator:
            return 'unknown'

        # Check for hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-f0-9]{32}$', indicator, re.IGNORECASE):
            return 'md5'
        elif re.match(r'^[a-f0-9]{40}$', indicator, re.IGNORECASE):
            return 'sha1'
        elif re.match(r'^[a-f0-9]{64}$', indicator, re.IGNORECASE):
            return 'sha256'

        # Check for IP addresses
        try:
            ip = ipaddress.ip_address(indicator.split(':')[0])  # Handle IP:port
            return 'ipv4' if isinstance(ip, ipaddress.IPv4Address) else 'ipv6'
        except ValueError:
            pass

        # Check for URLs
        if indicator.startswith(('http://', 'https://', 'ftp://', 'tcp://', 'udp://')):
            return 'url'

        # Check for file paths (contains / or \ and has extension)
        if ('/' in indicator or '\\' in indicator) and '.' in indicator.split('/')[-1]:
            return 'file_path'

        # Check for domains (contains dots, no spaces, valid domain pattern)
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\:[0-9]+)?$'
        if '.' in indicator and re.match(domain_pattern, indicator):
            return 'domain'

        return 'unknown'

    def parse_apt_file(self, filepath: Path) -> Tuple[Dict[str, Set[str]], Dict]:
        """
        Parse a single APT indicator file

        Returns: (indicators_dict, metadata_dict)
        """
        indicators = defaultdict(set)
        metadata = {
            'filename': filepath.name,
            'apt_group': filepath.stem.replace('apt_', '').upper(),
            'references': [],
            'aliases': [],
            'last_modified': datetime.fromtimestamp(filepath.stat().st_mtime).isoformat()
        }

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Parse comments for metadata
                if line.startswith('#'):
                    # Extract references
                    if 'Reference:' in line:
                        ref = line.split('Reference:', 1)[1].strip()
                        if ref.startswith(('http://', 'https://')):
                            metadata['references'].append(ref)
                    # Extract aliases
                    elif 'Aliases:' in line or 'Alias:' in line:
                        aliases = line.split(':', 1)[1].strip()
                        metadata['aliases'] = [a.strip() for a in aliases.split(',')]
                    continue

                # Classify and store indicator
                indicator_type = self.classify_indicator(line)
                if indicator_type != 'unknown':
                    indicators[indicator_type].add(line)

        return indicators, metadata

    def collect_all_indicators(self) -> None:
        """Collect all APT indicators from Maltrail repository"""
        apt_files = sorted(self.apt_files_path.glob("apt_*.txt"))

        print(f"Found {len(apt_files)} APT indicator files")

        for apt_file in apt_files:
            apt_name = apt_file.stem.replace('apt_', '').upper()
            indicators, metadata = self.parse_apt_file(apt_file)

            self.indicators[apt_name] = indicators
            self.metadata[apt_name] = metadata

            # Statistics for this APT
            total_indicators = sum(len(items) for items in indicators.values())
            if total_indicators > 0:
                print(f"  {apt_name}: {total_indicators} indicators collected")

    def export_json(self, output_file: str = "apttrail_threat_feed.json") -> None:
        """Export indicators to JSON format"""
        output = {
            'generated_at': datetime.now().isoformat(),
            'source': 'Maltrail APT Indicators',
            'total_apt_groups': len(self.indicators),
            'apt_groups': {}
        }

        for apt_name, indicators in self.indicators.items():
            # Convert sets to lists for JSON serialization
            indicators_dict = {k: list(v) for k, v in indicators.items()}

            output['apt_groups'][apt_name] = {
                'metadata': self.metadata.get(apt_name, {}),
                'indicators': indicators_dict,
                'statistics': {
                    'total': sum(len(v) for v in indicators.values()),
                    'by_type': {k: len(v) for k, v in indicators.items()}
                }
            }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"JSON feed exported to {output_file}")

    def export_csv(self, output_file: str = "apttrail_threat_feed.csv", compact: bool = True) -> None:
        """Export indicators to CSV format

        Args:
            output_file: Output CSV file path
            compact: If True, creates a compact version without duplicating metadata
        """
        if compact:
            # Compact format: just the essential IOC data
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['apt_group', 'indicator_type', 'indicator'])

                for apt_name, indicators in self.indicators.items():
                    for indicator_type, indicator_set in indicators.items():
                        for indicator in indicator_set:
                            writer.writerow([apt_name, indicator_type, indicator])

            # Also export a metadata file
            metadata_file = str(output_file).replace('.csv', '_metadata.csv')
            with open(metadata_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['apt_group', 'aliases', 'references'])

                for apt_name in self.indicators.keys():
                    metadata = self.metadata.get(apt_name, {})
                    aliases = ', '.join(metadata.get('aliases', []))
                    references = ' | '.join(metadata.get('references', []))
                    writer.writerow([apt_name, aliases, references])

            print(f"Compact CSV feed exported to {output_file}")
            print(f"Metadata exported to {metadata_file}")
        else:
            # Full format with all metadata (original - very large)
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['apt_group', 'indicator_type', 'indicator', 'aliases', 'references'])

                for apt_name, indicators in self.indicators.items():
                    metadata = self.metadata.get(apt_name, {})
                    aliases = ', '.join(metadata.get('aliases', []))
                    references = ' | '.join(metadata.get('references', []))

                    for indicator_type, indicator_set in indicators.items():
                        for indicator in indicator_set:
                            writer.writerow([apt_name, indicator_type, indicator, aliases, references])

            print(f"Full CSV feed exported to {output_file}")

    def export_stix(self, output_file: str = "apttrail_threat_feed_stix.json") -> None:
        """Export indicators to STIX 2.1 format"""
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{hashlib.uuid4().hex}",
            "objects": []
        }

        # Create threat actor objects for each APT group
        for apt_name, indicators in self.indicators.items():
            metadata = self.metadata.get(apt_name, {})

            # Create threat actor
            threat_actor = {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": f"threat-actor--{hashlib.md5(apt_name.encode()).hexdigest()[:8]}-0000-0000-0000-000000000000",
                "created": datetime.now().isoformat() + "Z",
                "modified": datetime.now().isoformat() + "Z",
                "name": f"APT {apt_name}",
                "threat_actor_types": ["nation-state", "hacktivist", "criminal"],
                "aliases": metadata.get('aliases', []),
                "external_references": [{"url": ref} for ref in metadata.get('references', [])]
            }
            stix_bundle["objects"].append(threat_actor)

            # Create indicators
            for indicator_type, indicator_set in indicators.items():
                for indicator_value in indicator_set:
                    # Create STIX pattern based on indicator type
                    if indicator_type == 'ipv4':
                        pattern = f"[network-traffic:dst_ref.value = '{indicator_value}']"
                    elif indicator_type == 'ipv6':
                        pattern = f"[network-traffic:dst_ref.value = '{indicator_value}']"
                    elif indicator_type == 'domain':
                        pattern = f"[domain-name:value = '{indicator_value}']"
                    elif indicator_type == 'url':
                        pattern = f"[url:value = '{indicator_value}']"
                    elif indicator_type in ['md5', 'sha1', 'sha256']:
                        pattern = f"[file:hashes.{indicator_type.upper()} = '{indicator_value}']"
                    elif indicator_type == 'file_path':
                        pattern = f"[file:name = '{indicator_value}']"
                    else:
                        continue

                    indicator_obj = {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": f"indicator--{hashlib.md5(indicator_value.encode()).hexdigest()[:8]}-0000-0000-0000-000000000000",
                        "created": datetime.now().isoformat() + "Z",
                        "modified": datetime.now().isoformat() + "Z",
                        "name": f"{apt_name} - {indicator_type}",
                        "pattern": pattern,
                        "pattern_type": "stix",
                        "valid_from": datetime.now().isoformat() + "Z",
                        "labels": ["malicious-activity"],
                        "description": f"Indicator associated with APT {apt_name}"
                    }
                    stix_bundle["objects"].append(indicator_obj)

                    # Create relationship between threat actor and indicator
                    relationship = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": f"relationship--{hashlib.md5(f'{apt_name}{indicator_value}'.encode()).hexdigest()[:8]}-0000-0000-0000-000000000000",
                        "created": datetime.now().isoformat() + "Z",
                        "modified": datetime.now().isoformat() + "Z",
                        "relationship_type": "indicates",
                        "source_ref": indicator_obj["id"],
                        "target_ref": threat_actor["id"]
                    }
                    stix_bundle["objects"].append(relationship)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(stix_bundle, f, indent=2, ensure_ascii=False)

        print(f"STIX bundle exported to {output_file}")

    def export_suricata(self, output_file: str = "apttrail_threat_feed.rules", optimized: bool = True, split_by_group: bool = False) -> None:
        """Export indicators to Suricata rules format

        Args:
            output_file: Output file path
            optimized: If True, generates one rule per indicator instead of multiple protocol rules
            split_by_group: If True, creates separate files for each APT group
        """
        sid_counter = 9000000  # Starting SID for custom rules

        if split_by_group:
            output_dir = Path(str(output_file).replace('.rules', ''))
            output_dir.mkdir(parents=True, exist_ok=True)

            for apt_name in self.indicators.keys():
                group_file = output_dir / f"apt_{apt_name.lower()}.rules"
                self._write_suricata_rules(group_file, {apt_name: self.indicators[apt_name]}, sid_counter, optimized)
                sid_counter += len(self.indicators[apt_name].get('domain', [])) * (1 if optimized else 3)
                sid_counter += len(self.indicators[apt_name].get('ipv4', [])) * (1 if optimized else 2)
                sid_counter += len(self.indicators[apt_name].get('url', [])) * 1

            print(f"Suricata rules split into {len(self.indicators)} files in {output_dir}")
            return

        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Maltrail APT Threat Feed - Suricata Rules\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write("# Source: https://github.com/stamparm/maltrail\n")
            f.write("#\n")
            f.write("# IMPORTANT: These are automatically generated rules for threat detection\n")
            f.write("# Review and test before deploying to production\n")
            f.write("#\n\n")

            for apt_name, indicators in self.indicators.items():
                metadata = self.metadata.get(apt_name, {})
                aliases = ', '.join(metadata.get('aliases', []))

                # Write APT group header
                f.write(f"# ==================================================\n")
                f.write(f"# APT Group: {apt_name}\n")
                if aliases:
                    f.write(f"# Aliases: {aliases}\n")
                f.write(f"# ==================================================\n\n")

                # Generate rules for domains
                if 'domain' in indicators:
                    f.write(f"# {apt_name} - Domain Indicators\n")
                    for domain in sorted(indicators['domain']):
                        if optimized:
                            # Single efficient rule using DNS OR HTTP OR TLS
                            rule = f'alert dns any any -> any any (msg:"APT {apt_name} - Malicious Domain {domain}"; dns.query; content:"{domain}"; nocase; classtype:trojan-activity; sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n'
                            f.write(rule)
                            sid_counter += 1
                        else:
                            # DNS query rule
                            rule = f'alert dns $HOME_NET any -> any any (msg:"APT {apt_name} - Suspicious DNS Query to {domain}"; dns.query; content:"{domain}"; nocase; classtype:trojan-activity; sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n'
                            f.write(rule)
                            sid_counter += 1

                            # HTTP Host header rule
                            rule = f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"APT {apt_name} - HTTP Connection to {domain}"; flow:established,to_server; http.host; content:"{domain}"; nocase; classtype:trojan-activity; sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n'
                            f.write(rule)
                            sid_counter += 1

                            # TLS SNI rule
                            rule = f'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"APT {apt_name} - TLS Connection to {domain}"; flow:established,to_server; tls.sni; content:"{domain}"; nocase; classtype:trojan-activity; sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n'
                            f.write(rule)
                            sid_counter += 1
                    f.write("\n")

                # Generate rules for IPs
                if 'ipv4' in indicators:
                    f.write(f"# {apt_name} - IPv4 Indicators\n")
                    for ip in sorted(indicators['ipv4']):
                        # Remove port if present
                        ip_clean = ip.split(':')[0]
                        if optimized:
                            # Single bidirectional rule
                            rule = f'alert ip any any <> {ip_clean} any (msg:"APT {apt_name} - Traffic to/from Malicious IP {ip}"; classtype:trojan-activity; threshold:type limit, track by_src, count 1, seconds 3600; sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n'
                            f.write(rule)
                            sid_counter += 1
                        else:
                            # Outbound connection rule
                            rule = f'alert ip $HOME_NET any -> {ip_clean} any (msg:"APT {apt_name} - Connection to Malicious IP {ip}"; classtype:trojan-activity; sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n'
                            f.write(rule)
                            sid_counter += 1

                            # Inbound connection rule
                            rule = f'alert ip {ip_clean} any -> $HOME_NET any (msg:"APT {apt_name} - Inbound Connection from Malicious IP {ip}"; classtype:trojan-activity; sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n'
                            f.write(rule)
                            sid_counter += 1
                    f.write("\n")

                # Generate rules for URLs
                if 'url' in indicators:
                    f.write(f"# {apt_name} - URL Indicators\n")
                    for url in sorted(indicators['url']):
                        # Extract domain and path from URL
                        try:
                            parsed = urllib.parse.urlparse(url)
                            if parsed.netloc:
                                # HTTP URL detection
                                rule = f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"APT {apt_name} - HTTP Request to Malicious URL"; flow:established,to_server; http.uri; content:"{parsed.path if parsed.path else "/"}"; http.host; content:"{parsed.netloc}"; nocase; classtype:trojan-activity; sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n'
                                f.write(rule)
                                sid_counter += 1
                        except:
                            pass
                    f.write("\n")

                # Generate rules for file hashes
                for hash_type in ['md5', 'sha1', 'sha256']:
                    if hash_type in indicators:
                        f.write(f"# {apt_name} - {hash_type.upper()} File Hash Indicators\n")
                        for file_hash in sorted(indicators[hash_type]):
                            # File hash detection rule
                            rule = f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"APT {apt_name} - Download of File with Known {hash_type.upper()} Hash"; flow:established,to_server; filestore; filemd5:!{file_hash}; classtype:trojan-activity; sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n'
                            f.write(rule)
                            sid_counter += 1
                        f.write("\n")

        print(f"Suricata rules exported to {output_file}")
        print(f"Total rules generated: {sid_counter - 9000000}")

    def generate_statistics(self) -> Dict:
        """Generate statistics about collected indicators"""
        stats = {
            'total_apt_groups': len(self.indicators),
            'total_indicators': 0,
            'indicators_by_type': defaultdict(int),
            'top_apt_groups': [],
            'apt_groups_list': []
        }

        apt_counts = []

        for apt_name, indicators in self.indicators.items():
            total = sum(len(items) for items in indicators.values())
            apt_counts.append((apt_name, total))
            stats['total_indicators'] += total
            stats['apt_groups_list'].append(apt_name)

            for indicator_type, items in indicators.items():
                stats['indicators_by_type'][indicator_type] += len(items)

        # Get top 10 APT groups by indicator count
        apt_counts.sort(key=lambda x: x[1], reverse=True)
        stats['top_apt_groups'] = apt_counts[:10]

        return stats

    def print_statistics(self) -> None:
        """Print statistics about collected indicators"""
        stats = self.generate_statistics()

        print("\n" + "="*60)
        print("APT THREAT FEED STATISTICS")
        print("="*60)
        print(f"Total APT Groups: {stats['total_apt_groups']}")
        print(f"Total Indicators: {stats['total_indicators']}")
        print("\nIndicators by Type:")
        for itype, count in sorted(stats['indicators_by_type'].items()):
            print(f"  {itype:15} : {count:,}")

        print("\nTop 10 APT Groups by Indicator Count:")
        for apt_name, count in stats['top_apt_groups']:
            print(f"  {apt_name:20} : {count:,} indicators")

        print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Maltrail APT Threat Feed Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Collect and export to all formats
  %(prog)s --json-only        # Export only to JSON format
  %(prog)s --no-update        # Skip repository update
  %(prog)s --output-dir feeds # Export to custom directory
        """
    )

    parser.add_argument('--maltrail-path', default='data/maltrail',
                        help='Path to Maltrail repository (default: data/maltrail)')
    parser.add_argument('--no-update', action='store_true',
                        help='Skip repository update')
    parser.add_argument('--json-only', action='store_true',
                        help='Export only JSON format')
    parser.add_argument('--csv-only', action='store_true',
                        help='Export only CSV format')
    parser.add_argument('--stix-only', action='store_true',
                        help='Export only STIX format')
    parser.add_argument('--suricata-only', action='store_true',
                        help='Export only Suricata rules format')
    parser.add_argument('--output-dir', default='.',
                        help='Output directory for feed files (default: current directory)')
    parser.add_argument('--stats', action='store_true',
                        help='Show statistics only, no export')

    args = parser.parse_args()

    # Create output directory if needed
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize collector
    collector = APTThreatFeedCollector(
        maltrail_path=args.maltrail_path,
        auto_update=not args.no_update
    )

    # Update repository
    if not args.no_update:
        collector.update_repository()

    # Collect indicators
    print("\nCollecting APT indicators...")
    collector.collect_all_indicators()

    # Print statistics
    collector.print_statistics()

    # Export based on arguments
    if not args.stats:
        if args.json_only:
            collector.export_json(output_dir / "apttrail_threat_feed.json")
        elif args.csv_only:
            collector.export_csv(output_dir / "apttrail_threat_feed.csv")
        elif args.stix_only:
            collector.export_stix(output_dir / "apttrail_threat_feed_stix.json")
        elif args.suricata_only:
            collector.export_suricata(output_dir / "apttrail_threat_feed.rules")
        else:
            # Export all formats
            print("\nExporting threat feeds...")
            collector.export_json(output_dir / "apttrail_threat_feed.json")
            collector.export_csv(output_dir / "apttrail_threat_feed.csv")
            collector.export_suricata(output_dir / "apttrail_threat_feed.rules")
            # Skip STIX by default as it's very large
            # collector.export_stix(output_dir / "apttrail_threat_feed_stix.json")

        print(f"\nAll feeds exported to {output_dir.absolute()}")


if __name__ == "__main__":
    main()