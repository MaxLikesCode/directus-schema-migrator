#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
from typing import Optional, Tuple

import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Migrate Directus schema from one instance to another. "
        "Credentials are loaded from .env file."
    )

    # Behavior options only - credentials come from .env
    p.add_argument(
        "--dry-run", action="store_true", help="Show diff only; do not apply."
    )
    p.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip backing up the target schema before applying.",
    )
    p.add_argument(
        "--timeout", type=int, default=30, help="HTTP timeout in seconds (default: 30)"
    )
    p.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable TLS verification (not recommended).",
    )
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON outputs.")
    p.add_argument(
        "--outdir",
        default=".",
        help="Where to write snapshot/diff files (default: current dir)",
    )

    args = p.parse_args()

    # Load credentials from environment variables
    args.source_url = os.getenv("DIRECTUS_SOURCE_URL")
    args.target_url = os.getenv("DIRECTUS_TARGET_URL")
    args.source_token = os.getenv("DIRECTUS_SOURCE_TOKEN")
    args.source_email = os.getenv("DIRECTUS_SOURCE_EMAIL")
    args.source_password = os.getenv("DIRECTUS_SOURCE_PASSWORD")
    args.target_token = os.getenv("DIRECTUS_TARGET_TOKEN")
    args.target_email = os.getenv("DIRECTUS_TARGET_EMAIL")
    args.target_password = os.getenv("DIRECTUS_TARGET_PASSWORD")

    # Validate required environment variables
    if not args.source_url or not args.target_url:
        p.error("DIRECTUS_SOURCE_URL and DIRECTUS_TARGET_URL must be set in .env file")

    return args


def login_if_needed(
    base_url: str,
    token: Optional[str],
    email: Optional[str],
    password: Optional[str],
    timeout: int,
    verify: bool,
) -> str:
    """
    Returns a Bearer token suitable for Authorization header.
    If `token` is provided, use it. Otherwise, attempt email/password login.
    """
    if token:
        return token

    if not (email and password):
        raise ValueError(f"No token or email/password provided for {base_url}")

    url = _join(base_url, "/auth/login")
    r = requests.post(
        url, json={"email": email, "password": password}, timeout=timeout, verify=verify
    )
    _raise_for_status(r, "Login failed")
    data = r.json().get("data") or {}
    access = data.get("access_token")
    if not access:
        raise RuntimeError("No access_token returned by Directus /auth/login")
    return access


def fetch_snapshot(base_url: str, bearer: str, timeout: int, verify: bool) -> dict:
    url = _join(base_url, "/schema/snapshot")
    r = requests.get(url, headers=_auth(bearer), timeout=timeout, verify=verify)
    _raise_for_status(r, "Fetching schema snapshot failed")
    body = r.json()
    if "data" not in body:
        raise RuntimeError("Unexpected snapshot response (missing 'data').")
    return body["data"]


def fetch_diff(
    base_url: str, bearer: str, snapshot: dict, timeout: int, verify: bool
) -> dict:
    url = _join(base_url, "/schema/diff")
    r = requests.post(
        url,
        headers=_auth(bearer),
        json=snapshot,
        timeout=timeout,
        verify=verify,
    )
    _raise_for_status(r, "Diff request failed")

    # Handle 204 No Content - means no differences
    if r.status_code == 204:
        return {
            "hash": None,
            "diff": {"collections": [], "fields": [], "relations": []},
        }

    # Parse JSON response
    body = r.json()
    if "data" not in body:
        raise RuntimeError("Unexpected diff response (missing 'data').")
    return body["data"]


def apply_snapshot(
    base_url: str, bearer: str, snapshot: dict, timeout: int, verify: bool
) -> dict:
    # Get the diff between source and target
    # The diff endpoint returns { hash: "...", diff: { collections: [...], fields: [...], ... } }
    diff_response = fetch_diff(base_url, bearer, snapshot, timeout, verify)

    # Extract hash and diff from the response
    if isinstance(diff_response, dict):
        if "hash" in diff_response and "diff" in diff_response:
            # New format: diff endpoint returns both hash and diff
            current_hash = diff_response["hash"]
            diff_data = diff_response["diff"]
        else:
            # Old format: diff endpoint returns just the diff, compute hash ourselves
            target_snapshot = fetch_snapshot(base_url, bearer, timeout, verify)
            schema_json = json.dumps(
                target_snapshot, sort_keys=True, separators=(",", ":")
            )
            current_hash = hashlib.sha256(schema_json.encode()).hexdigest()
            diff_data = diff_response
    else:
        raise RuntimeError(f"Unexpected diff response format: {type(diff_response)}")

    # Now apply the diff with the hash
    url = _join(base_url, "/schema/apply")
    payload = {"hash": current_hash, "diff": diff_data}

    r = requests.post(
        url,
        headers=_auth(bearer),
        json=payload,
        timeout=timeout,
        verify=verify,
    )
    _raise_for_status(r, "Applying schema snapshot failed")

    # Handle 204 No Content - successful apply with no response body
    if r.status_code == 204:
        return {"message": "Schema applied successfully (no response body)"}

    # Parse JSON response
    body = r.json()
    # Some Directus versions return { data: { operations: [...] } } or { data: null }
    return body.get("data")


def backup_target_schema(
    base_url: str, bearer: str, outdir: str, timeout: int, verify: bool
) -> Optional[str]:
    try:
        snap = fetch_snapshot(base_url, bearer, timeout, verify)
        path = os.path.join(outdir, "target_schema_backup.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)
        return path
    except Exception as e:
        print(f"[WARN] Failed to backup target schema: {e}")
        return None


def _auth(bearer: str) -> dict:
    return {
        "Authorization": f"Bearer {bearer}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _join(base: str, path: str) -> str:
    return f"{base.rstrip('/')}{path}"


def _raise_for_status(resp: requests.Response, context: str):
    try:
        resp.raise_for_status()
    except requests.HTTPError:
        # Try to surface Directus error details
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        raise requests.HTTPError(
            f"{context}: HTTP {resp.status_code} -> {detail}"
        ) from None


def summarize_diff(diff: dict) -> Tuple[int, dict]:
    """
    Diff shape varies by Directus version.
    Modern versions return: { hash: "...", diff: { collections: [...], fields: [...], relations: [...] } }
    Older versions return: { operations: [...] } or just [...]
    """
    count = 0
    by_type = {}

    # Handle new format: { hash: "...", diff: { collections: [...], fields: [...], relations: [...] } }
    if isinstance(diff, dict) and "diff" in diff:
        diff_data = diff["diff"]
        if isinstance(diff_data, dict):
            for category in ["collections", "fields", "relations"]:
                if category in diff_data and isinstance(diff_data[category], list):
                    for item in diff_data[category]:
                        # Each item has a "diff" array with operations
                        if isinstance(item, dict) and "diff" in item:
                            ops = item["diff"]
                            if isinstance(ops, list):
                                for op in ops:
                                    count += 1
                                    # kind: "N" (new), "D" (delete), "E" (edit)
                                    kind = (
                                        op.get("kind")
                                        if isinstance(op, dict)
                                        else "unknown"
                                    )
                                    key = f"{category}/{kind}"
                                    by_type[key] = by_type.get(key, 0) + 1
        return count, by_type

    # Handle old format: { operations: [...] } or just [...]
    ops = diff
    if isinstance(ops, dict) and "operations" in ops:
        ops = ops["operations"]

    if isinstance(ops, list):
        for op in ops:
            count += 1
            t = op.get("type") if isinstance(op, dict) else str(type(op))
            by_type[t] = by_type.get(t, 0) + 1

    return count, by_type


def write_json(path: str, obj: dict, pretty: bool):
    with open(path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        else:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))


def main():
    args = parse_args()
    verify = not args.no_verify_ssl

    print("== Directus Schema Migrator ==")
    print(f"Source: {args.source_url}")
    print(f"Target: {args.target_url}")
    print(f"Dry-run: {args.dry_run}")
    print(f"Backup target: {not args.no_backup}")
    print()

    # Authenticate
    try:
        source_bearer = login_if_needed(
            args.source_url,
            args.source_token,
            args.source_email,
            args.source_password,
            args.timeout,
            verify,
        )
        target_bearer = login_if_needed(
            args.target_url,
            args.target_token,
            args.target_email,
            args.target_password,
            args.timeout,
            verify,
        )
    except Exception as e:
        print(f"[ERROR] Authentication failed: {e}")
        sys.exit(1)

    # Fetch source snapshot
    try:
        print("[1/4] Fetching source schema snapshot…")
        source_snapshot = fetch_snapshot(
            args.source_url, source_bearer, args.timeout, verify
        )
    except Exception as e:
        print(f"[ERROR] Could not fetch source snapshot: {e}")
        sys.exit(1)

    # Save source snapshot to disk
    os.makedirs(args.outdir, exist_ok=True)
    snapshot_path = os.path.join(args.outdir, "source_schema_snapshot.json")
    write_json(snapshot_path, source_snapshot, args.pretty)
    print(f"Saved source snapshot -> {snapshot_path}")

    # Diff against target
    try:
        print("[2/4] Computing diff on target…")
        diff = fetch_diff(
            args.target_url, target_bearer, source_snapshot, args.timeout, verify
        )
        diff_path = os.path.join(args.outdir, "schema_diff.json")
        write_json(diff_path, diff, args.pretty)
        count, by_type = summarize_diff(diff)
        print(f"Diff operations: {count}")
        if by_type:
            print("By operation type:")
            for t, c in sorted(by_type.items(), key=lambda x: (-x[1], x[0])):
                print(f"  - {t}: {c}")
        print(f"Saved diff -> {diff_path}")
    except Exception as e:
        print(f"[ERROR] Could not compute diff on target: {e}")
        sys.exit(1)

    if args.dry_run:
        print("\nDry-run enabled. No changes applied.")
        sys.exit(0)

    # Check if there are any changes to apply
    if count == 0:
        print(
            "\n✅ No schema differences found. Target is already in sync with source."
        )
        sys.exit(0)

    # Backup (enabled by default)
    backup_path = None
    if not args.no_backup:
        print("[3/4] Backing up target schema…")
        backup_path = backup_target_schema(
            args.target_url, target_bearer, args.outdir, args.timeout, verify
        )
        if backup_path:
            print(f"Target backup saved -> {backup_path}")
        else:
            print("Target backup skipped (see warning above).")

    # Apply
    try:
        print("[4/4] Applying snapshot to target…")
        result = apply_snapshot(
            args.target_url, target_bearer, source_snapshot, args.timeout, verify
        )
        result_path = os.path.join(args.outdir, "apply_result.json")
        write_json(result_path, {"data": result}, args.pretty)
        print(f"Apply completed. Result saved -> {result_path}")
        print("\n✅ Schema migration completed successfully.")
        if backup_path:
            print(
                f"ℹ️ A backup of the previous target schema is available at: {backup_path}"
            )
    except Exception as e:
        print(f"[ERROR] Failed to apply snapshot on target: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
