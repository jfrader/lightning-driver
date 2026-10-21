#!/usr/bin/env python3
"""Validate fresh HTTP_EVIDENCE_DIR output from the real-adapter journeys.

Requires jsonschema (Draft 2020-12 with format checking); no schema fallback.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
FROZEN = {
    "api-server/openapi.json": "a7bd38f4dbf398f47617b1aa08fb216bbae12b357619ab4215548577a750cad5",
    "api-server/tests/fixtures/api-examples.json": "13adce818576f64d24303f99c0c86c54ee26d69ade4719142780ae2171f5ec66",
}
KINDS = {
    "create_invoice", "pay_invoice", "connect_peer", "disconnect_peer",
    "open_channel", "close_channel", "new_address", "send_onchain",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    for relative, expected in FROZEN.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected, relative
    contract = json.loads((ROOT / "api-server/openapi.json").read_text())
    files = sorted(args.evidence.glob("*.json"))
    assert files, "No actual journey responses; use a fresh evidence directory"
    schemas = Counter()
    succeeded = {kind: set() for kind in KINDS}
    states = Counter()
    for path in files:
        fixture = json.loads(path.read_text())
        name, value = fixture["schema"], fixture["value"]
        reference = name if name.startswith("#/") else f"#/components/schemas/{name}"
        Draft202012Validator(
            {"$ref": reference, "components": contract["components"]},
            format_checker=FormatChecker(),
        ).validate(value)
        schemas[name] += 1
        if name == "Operation":
            states[value["state"]] += 1
            if value["state"] == "succeeded":
                succeeded[value["request"]["kind"]].add(value["id"])
        serialized = json.dumps(value)
        for canary in ("SYNTHETIC_DEV_RUNE", "SYNTHETIC_DEV_MACAROON", "PREIMAGE_CANARY", "RAW_TX_CANARY", "PSBT_CANARY"):
            assert canary not in serialized, (path.name, canary)
    assert all(len(ids) >= 3 for ids in succeeded.values()), succeeded
    assert states["unknown"] > 0 and states["pending"] > 0 and states["failed"] > 0, states
    assert schemas["AuthorizationStart"] > 0 and schemas["OperationAuthorization"] > 0, schemas
    print(json.dumps({"validated": len(files), "schemas": schemas, "operation_states": states,
                      "distinct_succeeded_by_kind": {k: len(v) for k, v in succeeded.items()}}, indent=2))


if __name__ == "__main__":
    main()
