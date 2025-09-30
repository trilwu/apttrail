# 🛡️ APTtrail - Automated APT Threat Feed Collector

[![Collect APT Threat Feeds](https://github.com/trilwu/apttrail/actions/workflows/collect-apt-feeds.yml/badge.svg)](https://github.com/trilwu/apttrail/actions/workflows/collect-apt-feeds.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Automated collection of APT (Advanced Persistent Threat) indicators from [Maltrail](https://github.com/stamparm/maltrail). Updates hourly with ready-to-use threat feeds in JSON, CSV, STIX 2.1, and optimized Suricata/Snort rules.

## 💡 Why This Project?

**Maltrail** is one of the best **free, open-source threat intelligence feeds** available, maintained by security researcher Miroslav Stampar. It provides 120,000+ indicators covering 323+ APT groups with exceptional data quality.

**The Problem:** Maltrail's data is scattered across hundreds of trail files, making it difficult to consume programmatically.

**The Solution:** APTtrail automatically extracts, normalizes, and publishes all APT indicators in multiple formats - updated hourly via GitHub Actions. Zero infrastructure needed.

## 🚀 Quick Start

### Deploy Suricata Rules (Recommended)

Download and deploy 117,000 optimized detection rules:

```bash
# Download rules
curl -O https://raw.githubusercontent.com/trilwu/apttrail/main/feeds/apttrail_threat_feed.rules

# Deploy to Suricata
sudo cp apttrail_threat_feed.rules /etc/suricata/rules/
sudo systemctl restart suricata
```

Or add to `/etc/suricata/suricata.yaml`:
```yaml
rule-files:
  - apttrail_threat_feed.rules
```

**Rule Features:**
- 117K optimized rules (70% smaller than unoptimized)
- DNS, IP, HTTP URL, and file hash detection
- Bidirectional IP blocking with rate limiting
- SID range: 9000000-9116772
- Compatible with Suricata 6.x+ and Snort 3.x

### Use Other Feed Formats

Download feeds from the [feeds directory](feeds/):

```bash
# JSON feed (120K+ indicators)
curl -O https://raw.githubusercontent.com/trilwu/apttrail/main/feeds/apttrail_threat_feed.json

# CSV feed (compact format)
curl -O https://raw.githubusercontent.com/trilwu/apttrail/main/feeds/apttrail_threat_feed.csv

# STIX 2.1 format
curl -O https://raw.githubusercontent.com/trilwu/apttrail/main/feeds/apttrail_threat_feed_stix.json
```

### Run Your Own Instance

1. **Fork this repository**
2. **Enable GitHub Actions** in Settings → Actions → General
3. **Done!** Feeds update hourly automatically

Customize the schedule in [.github/workflows/collect-apt-feeds.yml](.github/workflows/collect-apt-feeds.yml)

## 📁 Feed Formats

**Suricata Rules** (`apttrail_threat_feed.rules`) - 117K optimized detection rules
- DNS, IP, HTTP URL, file hash detection
- Bidirectional blocking with rate limiting
- 70% smaller than unoptimized rules

**JSON** (`apttrail_threat_feed.json`) - Full structured data with metadata
**CSV** (`apttrail_threat_feed.csv`) - Compact format: `apt_group,type,indicator`
**STIX 2.1** (`apttrail_threat_feed_stix.json`) - Industry-standard threat intel format

## 📊 Statistics

- **APT Groups:** 323+
- **Total Indicators:** 120,000+
- **Suricata Rules:** 117,000 (optimized)
- **Update Frequency:** Hourly
- **Data Source:** [Maltrail](https://github.com/stamparm/maltrail)

## 🙏 Acknowledgments

Built on [Maltrail](https://github.com/stamparm/maltrail) by Miroslav Stampar - one of the best free, open-source threat intelligence feeds available.

## 📝 License

MIT License. Maltrail data subject to [Maltrail license](https://github.com/stamparm/maltrail/blob/master/LICENSE).

---

⚠️ **Disclaimer:** Always verify indicators before defensive action. Use at your own risk.
