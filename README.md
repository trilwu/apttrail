# APTtrail

**IOCs that tell you whose they are.** ~167,000 indicators from ~340 APT groups,
121 of them resolved onto 95 MITRE ATT&CK intrusion sets, refreshed hourly.

[![CI](https://github.com/trilwu/apttrail/actions/workflows/ci.yml/badge.svg)](https://github.com/trilwu/apttrail/actions/workflows/ci.yml)
[![indicators](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Ftrilwu.github.io%2Fapttrail%2Findex.json&query=%24.totals.indicators&label=indicators&color=blue)](https://trilwu.github.io/apttrail/)
[![ATT&CK groups](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Ftrilwu.github.io%2Fapttrail%2Findex.json&query=%24.totals.attack_groups&label=ATT%26CK%20groups&color=blue)](https://trilwu.github.io/apttrail/)
[![updated](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Ftrilwu.github.io%2Fapttrail%2Findex.json&query=%24.generated_at&label=updated&color=green)](https://trilwu.github.io/apttrail/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Most free IOC feeds hand you a flat list of bad domains. Actor attribution lives
somewhere else, in a different format, joined by hand through alias tables.
APTtrail ships them together: every indicator arrives tagged with the group it
belongs to, and where MITRE tracks that group, with its `Gxxxx` id.

```bash
# Every domain APT28 (G0007) has ever been seen using
curl -sL https://trilwu.github.io/apttrail/by-group/G0007-domain.txt
```

Browse it: **[trilwu.github.io/apttrail](https://trilwu.github.io/apttrail/)** —
every group has a profile page with description, suspected origin, targeted
sectors, ATT&CK techniques, and a timeline of its indicators: each batch dated
and linked to the report it came from, e.g.
[APT28](https://trilwu.github.io/apttrail/by-group/G0007.html).

---

## 60-second start

Everything is a static file on a stable URL. No account, no API key, no rate limit.

Slices are served over GitHub Pages; the big single-file formats are release
assets. Both have stable URLs you can construct by hand.

```bash
SITE=https://trilwu.github.io/apttrail
REL=https://github.com/trilwu/apttrail/releases/download/latest

curl -sLO $SITE/by-type/domain.txt          # every domain, one per line
curl -sLO $SITE/by-type/ipv4.txt            # every IP, ports stripped
curl -sLO $SITE/by-group/G0007.json         # one actor, full detail
curl -sLO $SITE/index.json                  # what exists, with counts
curl -sLO $REL/apttrail_threat_feed_stix.json
```

| Doing this | Grab this |
|---|---|
| Blocklist for pfBlockerNG / Pi-hole / firewall | `by-type/domain.txt`, `by-type/ipv4.txt` |
| Hunting one actor in DNS or proxy logs | `by-group/<G-id>-domain.txt` |
| Loading into MISP | `misp-feed/` (add the URL as a MISP Feed) |
| Loading into OpenCTI or any STIX tool | `apttrail_threat_feed_stix.json` |
| Suricata / Snort IDS | `apttrail_threat_feed.rules` + `suricata-datasets/` |
| Sigma-based SIEM | `apttrail_threat_feed.yaml` (one rule per group, ATT&CK-tagged) |
| Looking up one indicator from an alert | [`search.html`](https://trilwu.github.io/apttrail/search.html) or `by-indicator/<shard>.json` |
| Reading up on an actor | [`by-group/<G-id>.html`](https://trilwu.github.io/apttrail/by-group/G0007.html) |
| Seeing what moved this week | [`activity.html`](https://trilwu.github.io/apttrail/activity.html) / `activity.json` |
| Your own tooling | `apttrail_threat_feed.json`, `.csv`, `index.json` |

`weekly-YYYY-Wxx` tags are immutable snapshots if you need a fixed point in time
for an investigation.

---

## What attribution buys you

An alert says `evil-domain.example`. With a flat blocklist that is where the
story ends. Here:

```console
$ SITE=https://trilwu.github.io/apttrail

$ curl -s $SITE/by-group/G0007.json | jq '{attack_id, attack_name, attack_url, counts}'
{
  "attack_id": "G0007",
  "attack_name": "APT28",
  "attack_url": "https://attack.mitre.org/groups/G0007/",
  "counts": { "domain": 1431, "ipv4": 240, "url": 144, "url_path": 79 }
}

$ curl -s $SITE/by-group/G0040.json | jq '.maltrail_groups'
["DONOT", "HANGOVER", "PATCHWORK"]
```

Going the other way — an alert fires on a domain and you want to know whose it is:

```bash
# one-off lookup across every group, no local copy needed
curl -s $SITE/index.json | jq -r '.groups[] | select(.counts.domain) | .slug' \
  | while read -r slug; do
      curl -s "$SITE/by-group/$slug-domain.txt" \
        | grep -qFx "evil-domain.example" && echo "$slug"
    done
```

For repeated lookups, pull `by-type/domain.txt` once and keep the whole set local.

Either direction, you land one hop from the actor's ATT&CK page, their full
infrastructure set, and the 22 aliases other vendors' reporting will use for the
same group.

The id travels into every format, so it survives the trip into your tooling:

- **Suricata** — `metadata:apt_group SOFACY, mitre_group_id G0007;`
- **MISP** — a `misp-galaxy:mitre-intrusion-set` tag, so the event pivots to the cluster
- **STIX** — an `intrusion-set` with an `external_references` entry to ATT&CK
- **JSON / CSV** — `attack_id`, `attack_name`, `attack_url` per group

Alias resolution is vendored from the [MISP galaxy](https://github.com/MISP/misp-galaxy),
so it works offline and is reproducible. Refresh with
`python scripts/refresh_attack_groups.py`.

---

## Per-tool setup

<details>
<summary><b>Suricata</b></summary>

```bash
BASE=https://github.com/trilwu/apttrail/releases/download/latest
curl -sLO $BASE/apttrail_threat_feed.rules
curl -sLO $BASE/apttrail_suricata_datasets.tar.gz
tar xzf apttrail_suricata_datasets.tar.gz -C /etc/suricata/rules/

cp apttrail_threat_feed.rules /etc/suricata/rules/
suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/apttrail_threat_feed.rules
```

~4,100 rules, not 150,000: domains and IPs are matched through Suricata
`dataset:` lookups rather than one rule per indicator. SIDs occupy the
`9000000+` local range, clear of Emerging Threats.

Every published rule file has been through `suricata -T` in CI before release —
see [Verification](#verification).
</details>

<details>
<summary><b>MISP</b></summary>

Add as a feed under *Sync Actions → Feeds → Add Feed*:

- Input source: `Network`
- Format: `MISP Feed`
- URL: `https://trilwu.github.io/apttrail/misp-feed/`

That URL is a real MISP feed — `manifest.json`, one event per APT group, and
`hashes.csv` for correlation. **One event per actor**, not one event with
155,000 attributes, so you can pivot from a hit to that group's full
infrastructure. Events carry `tlp:clear`, `apt:<group>` and, where the group is
mapped, the `misp-galaxy:mitre-intrusion-set` tag that links to the actor
cluster. Attributes have `to_ids` set.

Event and attribute UUIDs are deterministic, so re-fetching updates events in
place instead of duplicating them. For an air-gapped instance,
`apttrail_misp_feed.tar.gz` in the release has the same directory.
</details>

<details>
<summary><b>OpenCTI / STIX 2.1</b></summary>

```bash
curl -sLO https://github.com/trilwu/apttrail/releases/download/latest/apttrail_threat_feed_stix.json
```

The bundle contains `intrusion-set` objects (not `threat-actor`), so it merges
with ATT&CK data already in your platform instead of creating duplicates.
Object ids are UUIDv5 over a fixed namespace: re-ingesting updates objects
rather than multiplying them.
</details>

<details>
<summary><b>pfBlockerNG / Pi-hole / firewall</b></summary>

Point at the flat lists; they are plain text with `#` comments.

```
https://trilwu.github.io/apttrail/by-type/domain.txt
https://trilwu.github.io/apttrail/by-type/ipv4.txt
```

Read the [caveats](#honest-limitations) before blocking on these outright.
</details>

<details>
<summary><b>Splunk / Sentinel / anything with a lookup table</b></summary>

```bash
curl -sL https://github.com/trilwu/apttrail/releases/download/latest/apttrail_threat_feed.csv -o apttrail.csv
# apt_group,indicator_type,indicator[,first_seen]
```

`apttrail_threat_feed_metadata.csv` maps each group to its ATT&CK id, name,
URL and aliases, so you can enrich a match without a second lookup.
</details>

---

## What is in the feed

| Type | Count | Notes |
|---|---|---|
| `domain` | ~141,000 | |
| `url_path` | ~3,600 | bare request paths, e.g. `/gate.php` |
| `ipv4` | ~3,800 | ports recorded separately, addresses are bare |
| `url` | ~3,200 | includes scheme-less `host/path` |
| hashes | 0 | Maltrail's APT trails carry none today |

~340 Maltrail groups, 121 of which resolve onto 95 distinct ATT&CK intrusion
sets. Groups that ATT&CK treats as one actor are merged into one slice, so
`G0040` covers DONOT, PATCHWORK and HANGOVER together. Largest: GAMAREDON (G0047, 52,028),
KIMSUKY (G0094, 25,227), TRANSPARENTTRIBE (G0134, 7,776), LAZARUS (G0032, 5,346).

### Indicator history

Three records, none of which requires diffing a 7MB file:

- **`first_seen`** — when an indicator entered *Maltrail*, with a
  `first_seen_precision` of `exact` or `at-or-before`.

  This took recovering history that upstream had thrown away. Maltrail reset its
  repository on 2026-01-03 ("Initial commit (fresh repo)"), and `git blame`
  cannot see past a root commit, so a naive reading dates every older indicator
  to January 2026 — which is what this feed used to publish. The discarded
  history survives in pre-reset pull-request refs; walking one of them recovers
  the commit that first added each line, back to 2014.

  Today **126,915 indicators carry an exact date spanning 2015–2026**. 4,646
  fall in the gap between the recovered history and the reset and are marked
  `at-or-before` — they may be older. 23,649 stay undated rather than guessed
  at. Regenerate the map with the *Backfill IOC history* workflow.
- **the report each indicator came from.** Maltrail files indicators under the
  write-up that published them:

  ```text
  # Reference: https://vendor.example/apt28-write-up
  evil.example
  1.2.3.4
  ```

  That association is the only per-indicator provenance upstream carries, and
  flattening it into one list per group — which is what this project used to do —
  left an analyst with 1,600 references at the foot of a page and no way to tell
  which one explains the domain in front of them. It is now kept: `by-group/<G-id>.json`
  carries a `timeline` of `(date, report, indicators)` batches, and the actor
  page renders it, newest first, each batch linked to its source. 9,837 batches
  cover 155,190 indicators; exactly one of them has no report behind it.

  ```bash
  # Which report brought this domain in, and when?
  curl -s $SITE/by-group/G0007.json |
    jq '.timeline[] | select(.indicators.domain // [] | index("evil.example"))'
  ```
- **`changes/YYYY-MM.jsonl`** — when an indicator entered or **left** APTtrail,
  which `first_seen` cannot express. Append-only, a few KB per day, kept in git:

```json
{"action":"added","group":"BLUENOROFF","ts":"2026-07-26T04:00:00","type":"domain","value":"example.com"}
```

```bash
grep '"value":"example.com"' feeds/changes/*.jsonl   # when did we see this, and when did it go
```

---

## Honest limitations

- **Attribution covers 121 of ~340 groups (36%).** ATT&CK tracks 191 intrusion sets;
  Maltrail tracks actors from vendor reporting that ATT&CK has not named. An
  unmapped group still carries its Maltrail name and aliases.
- **These are historical indicators, not a real-time blocklist.** Domains get
  reused and sinkholed. Treat a hit as a lead to triage, not proof of compromise,
  and expect false positives if you block `domain.txt` wholesale. `first_seen`
  tells you how old an indicator is — much of the feed predates 2022 — so filter
  on age if you intend to block rather than hunt.
- **Attribution is inherited, not independent.** APTtrail trusts Maltrail's
  group assignment and the MISP galaxy's alias table. It does no analysis of
  its own.
- **No file hashes.** The YARA output therefore matches indicator *strings*
  inside files and memory, which also hits benign files that merely mention a
  domain — logs, PCAPs, this feed itself. Its header says so. If you want hash
  detection, this is not your feed.
- **One upstream source.** Everything here derives from
  [Maltrail](https://github.com/stamparm/maltrail). Its coverage is your coverage.

---

## Verification

Feeds are not published on trust:

- CI runs the real Suricata engine (`suricata -T`) over rules built from a
  fixture covering every rule shape, including a live indicator containing a
  double quote and a URL with no path.
- The hourly workflow runs `suricata -T` over the actual rule file and
  **refuses to publish** if it fails.
- Sigma output is parsed as multi-document YAML in the test suite; every rule
  must have a condition naming only selections that exist and hold values.
- The MISP feed layout is asserted against what MISP reads: manifest keys
  matching event files, stable UUIDs across runs, galaxy tags where mapped.
- 208 tests, `mypy` clean, `ruff` clean, coverage 91% against a gate of 80%.

---

## Running it yourself

```bash
pip install -e .
apttrail --output-dir feeds --suricata-dataset --collect-timestamps
```

```bash
docker build -t apttrail . && docker run -v $(pwd)/feeds:/app/feeds apttrail
```

Useful flags: `--json-only`, `--slices-only`, `--misp-only`, `--no-update`,
`--cache-dir`, `--no-changelog`. Full list with `apttrail --help`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Indicator data originates from
[Maltrail](https://github.com/stamparm/maltrail) by Miroslav Stampar — the
project this one stands on. Alias data from the
[MISP galaxy](https://github.com/MISP/misp-galaxy), CC-BY-SA.
