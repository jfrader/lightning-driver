#!/usr/bin/env python3
"""Validate fresh HTTP_EVIDENCE_DIR output from the real-adapter journeys.

Requires jsonschema (Draft 2020-12 with format checking); no schema fallback.
"""
import argparse
from copy import deepcopy
from collections import Counter
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
FROZEN = {
    "api-server/openapi.json": "a9aa7112084ec1a0cc8ca84157e4f9b750eb1cb3a2a96133cc494fa597327717",
    "api-server/tests/fixtures/api-examples.json": "e5af66a0b8ba6f390eb86a247a763800cd173034fd166ae8f2c0b0ae7c5c86f9",
}
KINDS = {
    "create_invoice", "pay_invoice", "connect_peer", "disconnect_peer",
    "open_channel", "close_channel", "new_address", "send_onchain",
}


def validator(contract, name):
    reference = name if name.startswith("#/") else f"#/components/schemas/{name}"
    return Draft202012Validator(
        {"$ref": reference, "components": contract["components"]},
        format_checker=FormatChecker(),
    )


def validate_examples(contract):
    fixtures = json.loads((ROOT / "api-server/tests/fixtures/api-examples.json").read_text())["fixtures"]
    for name, fixture in fixtures.items():
        errors = list(validator(contract, fixture["schema"]).iter_errors(fixture["value"]))
        assert not errors, (name, [error.message for error in errors])

    def reject(name, mutate):
        fixture = fixtures[name]
        value = deepcopy(fixture["value"])
        mutate(value)
        assert not validator(contract, fixture["schema"]).is_valid(value), (name, value)

    for key in fixtures["node_bitcoin"]["value"]["read_availability"]:
        reject("node_bitcoin", lambda value, key=key: value["read_availability"].pop(key))
    for reason in ["node_offline", "syncing", "unverified", "monitor_only", "read_only"]:
        reject("node_bitcoin", lambda value, reason=reason: value["read_availability"].update(
            bitcoin={"enabled": False, "reason": reason}))
    for capability in [{"enabled": True, "reason": "unsupported"}, {"enabled": False, "reason": None}]:
        reject("node_bitcoin", lambda value, capability=capability: value["read_availability"].update(bitcoin=capability))
    for progress in [10000, 0.5, "10001", "-1", "01", "1.0"]:
        reject("bitcoin_info", lambda value, progress=progress: value.update(verification_progress_bp=progress))
    for key in ["prune_height", "connections_in", "connections_out"]:
        reject("bitcoin_info", lambda value, key=key: value.pop(key))
    for transport in ["tor", "unknown"]:
        reject("bitcoin_peers_page", lambda value, transport=transport: value["items"][0].update(network=transport))
    for session_id in ["", "A" * 43, "A" * 45, "!" * 44]:
        reject("watchtower_tower_detail", lambda value, session_id=session_id: value["session_info"][0]["sessions"][0].update(id=session_id))
    reject("watchtower_server", lambda value: value.update(active=True))
    reject("watchtower_client", lambda value: value["stats"].update(scope="lifetime"))
    for name in ["bitcoin_info", "bitcoin_peers_page", "watchtower_server", "watchtower_client", "watchtower_towers_page", "watchtower_tower_detail"]:
        reject(name, lambda value: value.update(unexpected=True))
    print(f"Validated {len(fixtures)} contract examples and monitoring boundary rejections")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, nargs="?")
    parser.add_argument("--examples-only", action="store_true")
    args = parser.parse_args()
    if not args.examples_only and args.evidence is None:
        parser.error("evidence is required unless --examples-only is specified")
    for relative, expected in FROZEN.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected, relative
    contract = json.loads((ROOT / "api-server/openapi.json").read_text())
    for schema in contract["components"]["schemas"].values():
        Draft202012Validator.check_schema(schema)
    validate_examples(contract)
    if args.examples_only:
        return
    files = sorted(args.evidence.glob("*.json"))
    assert files, "No actual journey responses; use a fresh evidence directory"
    schemas = Counter()
    succeeded = {kind: set() for kind in KINDS}
    states = Counter()
    for path in files:
        fixture = json.loads(path.read_text())
        name, value = fixture["schema"], fixture["value"]
        validator(contract, name).validate(value)
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
