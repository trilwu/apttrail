# APTtrail - APT Threat Feed Collector

**APTtrail** is an automated threat intelligence collector that processes indicators from the [Maltrail](https://github.com/stamparm/maltrail) repository into multiple standard formats.

[![CI](https://github.com/trilwu/apttrail/actions/workflows/ci.yml/badge.svg)](https://github.com/trilwu/apttrail/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

- **Multi-Format Export**: JSON, CSV, STIX 2.1, Suricata, YARA, MISP, and Sigma.
- **Git Integration**: Auto-updates source repository and extracts commit timestamps.
- **Optimized**: Generates high-performance Suricata rules (regex-optimized).
- **Type-Safe**: Fully typed Python codebase with Pydantic validation.
- **Dockerized**: Ready-to-use container image.

## 📦 Installation

### From Source
```bash
git clone https://github.com/trilwu/apttrail.git
cd apttrail
pip install -e .
```

### Using Docker
```bash
docker build -t apttrail .
docker run -v $(pwd)/feeds:/app/feeds apttrail --json-only
```

## 🛠 Usage

Basic usage (collects all feeds):
```bash
apttrail
```

Custom output directory:
```bash
apttrail --output-dir /path/to/feeds
```

Specific formats:
```bash
apttrail --json-only     # JSON only
apttrail --csv-only      # CSV only
apttrail --stix-only     # STIX 2.1 bundle
apttrail --misp-only     # MISP event JSON
apttrail --sigma-only    # Sigma detection rules
apttrail --yara-only     # YARA rules
```

Enable timestamp collection (slower, uses `git blame`):
```bash
apttrail --collect-timestamps
```

## 📥 Getting the feeds

Feeds are published as **release assets**, not committed to the repository —
hourly commits of multi-megabyte files are what previously grew this repo to
841MB. The `latest` tag is updated every hour and its URLs are stable:

```bash
curl -LO https://github.com/trilwu/apttrail/releases/download/latest/apttrail_threat_feed.json
curl -LO https://github.com/trilwu/apttrail/releases/download/latest/apttrail_threat_feed.rules
```

Swap the filename for any format in the table below. `weekly-YYYY-Wxx` tags hold
immutable snapshots if you need a fixed point in time.

## 📊 Output Formats

| Format | File | Description |
|--------|------|-------------|
| **JSON** | `apttrail_threat_feed.json` | Full structured data with metadata |
| **CSV** | `apttrail_threat_feed.csv` | Compact list of indicators |
| **STIX** | `apttrail_threat_feed_stix.json` | STIX 2.1 Bundle |
| **Suricata** | `apttrail_threat_feed.rules` | Detection rules for IDS |
| **YARA** | `apttrail_threat_feed.yar` | File scanning rules |
| **MISP** | `apttrail_threat_feed_misp.json` | MISP Event format |
| **Sigma** | `apttrail_threat_feed.yaml` | Generic detection rules |
| **Changelog** | `changes/YYYY-MM.jsonl` | Append-only log of indicator additions and removals |

## 🕰 Indicator history

Two complementary records answer "when did this indicator change?" without
diffing multi-megabyte feed files:

- **`first_seen`** — when an indicator entered *Maltrail*, derived from the
  upstream repository's own git history. Present in the JSON feed when
  collection is enabled (`--collect-timestamps`, on by default in CI).
- **`feeds/changes/YYYY-MM.jsonl`** — when an indicator entered or **left** the
  APTtrail feed, which `first_seen` cannot express. This is the one feed
  artifact kept in git, because it is small and append-only. One JSON object
  per event:

```json
{"action":"added","group":"BLUENOROFF","ts":"2026-07-26T04:00:00","type":"domain","value":"example.com"}
```

Query it directly, no tooling required:

```bash
grep '"value":"example.com"' feeds/changes/*.jsonl
```

Weekly release tags (`weekly-YYYY-Wxx`) provide immutable point-in-time
snapshots of the full feed, including the STIX and MISP bundles that are too
large to store in git.

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgements

- [Maltrail](https://github.com/stamparm/maltrail) by Miroslav Stampar for the incredible data source.
