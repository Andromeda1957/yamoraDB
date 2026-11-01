"""Exercise a new, empty writable daemon using only Python's standard library."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from yamora import YamoraClient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--read-token-file", required=True)
    parser.add_argument("--write-token-file", required=True)
    args = parser.parse_args()
    client = YamoraClient(
        host=args.host,
        port=args.port,
        auth_token_file=args.read_token_file,
        write_auth_token_file=args.write_token_file,
    )
    examples = Path(__file__).resolve().parent
    client.put("people", "alex", (examples / "people/alex.yaml").read_bytes(), create_only=True)
    client.create_index("people", "active-age", ["active", "profile.age"])

    # Publish all three document changes as one revision.
    client.transaction(
        [
            {
                "collection": "people",
                "document": "sam",
                "put": (examples / "people/sam.yaml").read_bytes(),
                "create_only": True,
            },
            {
                "collection": "inventory",
                "document": "tea",
                "put": (examples / "inventory/tea.yaml").read_bytes(),
                "create_only": True,
            },
            {
                "collection": "people",
                "document": "alex",
                "patch": json.loads((examples / "patch.json").read_text()),
            },
        ],
        revision=client.snapshot_revision(),
    )
    result = client.query("people", json.loads((examples / "query.json").read_text()))
    assert result["matched"] == 2
    assert [item["id"] for item in result["documents"]] == ["sam", "alex"]
    assert result["documents"][1]["value"]["orders"] == 4
    raw = client.get("people", "alex")
    assert b"# Keep this note beside the editable source document." in raw
    assert b"# Home city" in raw
    assert client.count("inventory", {"variants": {"$elemMatch": {"stock": {"$gte": 10}}}}) == 1
    print(json.dumps(result, indent=2))
    print("Created people and inventory documents; comments survived the atomic update.")


if __name__ == "__main__":
    main()
