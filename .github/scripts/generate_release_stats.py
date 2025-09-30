#!/usr/bin/env python3
import json
import sys

with open('release-feeds/apttrail_threat_feed.json') as f:
    data = json.load(f)
    print(f"- **APT Groups:** {data['total_apt_groups']}")
    total = 0
    types = {}
    for group in data['apt_groups'].values():
        total += group['statistics']['total']
        for itype, count in group['statistics']['by_type'].items():
            types[itype] = types.get(itype, 0) + count
    print(f'- **Total Indicators:** {total:,}')
    print()
    print('### Indicators by Type:')
    for itype, count in sorted(types.items()):
        print(f'- {itype}: {count:,}')