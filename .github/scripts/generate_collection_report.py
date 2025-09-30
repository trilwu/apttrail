#!/usr/bin/env python3
import json
import sys
from datetime import datetime

with open('feeds/apttrail_threat_feed.json') as f:
    data = json.load(f)

    # Calculate total indicators
    total = 0
    for group in data['apt_groups'].values():
        total += group['statistics']['total']

    # Get top 3 groups
    groups = [(name, group['statistics']['total']) for name, group in data['apt_groups'].items()]
    groups.sort(key=lambda x: x[1], reverse=True)
    top3 = ', '.join([f"{name} ({count:,})" for name, count in groups[:3]])

    # Calculate indicator type distribution
    type_totals = {}
    for group in data['apt_groups'].values():
        for itype, count in group['statistics']['by_type'].items():
            type_totals[itype] = type_totals.get(itype, 0) + count
    top_types = sorted(type_totals.items(), key=lambda x: x[1], reverse=True)[:3]
    types_summary = ', '.join([f"{t}: {c:,}" for t, c in top_types])

    # Short commit-friendly summary
    print(f"Update APT threat feeds: {data['total_apt_groups']} groups, {total:,} indicators")
    print()
    print(f"Top 3 groups: {top3}")
    print(f"Top types: {types_summary}")

    # Detailed section for commit body
    print()
    print("---")
    print()
    print(f"Total APT Groups: {data['total_apt_groups']}")
    print(f"Total Indicators: {total:,}")
    print()
    print("Top 10 APT Groups:")
    for i, (name, count) in enumerate(groups[:10], 1):
        print(f"  {i}. {name}: {count:,}")

    print()
    print("Indicator Types:")
    for itype, count in sorted(type_totals.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {itype}: {count:,}")