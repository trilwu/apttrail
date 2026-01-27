
import json
import sys
from pathlib import Path

def normalize_timestamp(file_path):
    file = Path(file_path)
    if not file.exists():
        print(f"File not found: {file_path}")
        return

    try:
        data = json.loads(file.read_text(encoding='utf-8'))
        # Set to a fixed timestamp for comparison to avoid false positives in git diff
        data['generated_at'] = '2024-01-01T00:00:00'
        
        # Write back with deterministic formatting
        file.write_text(
            json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False),
            encoding='utf-8'
        )
        print(f"Normalized timestamp in {file_path}")
    except Exception as e:
        print(f"Error normalizing {file_path}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        normalize_timestamp(sys.argv[1])
    else:
        normalize_timestamp('feeds/apttrail_threat_feed.json')
