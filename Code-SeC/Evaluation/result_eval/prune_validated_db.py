#!/usr/bin/env python
# coding: utf-8
"""Drop the negative verdicts from a validated_secrets_db.json.

Entries that already came back real are kept, so a re-validation run reuses them
for free; everything else is dropped so the fixed validators get another look at
it. The database is rewritten in place after a .prune-backup copy is made.
"""
import argparse
import json
import os
import shutil
import sys


def prune(db_path, dry_run=False, drop_statuses=()):
    with open(db_path, "r", encoding="utf-8") as fh:
        db = json.load(fh)

    def keep(entry):
        # A positive verdict is only worth reusing if the validator that issued
        # it is still the one we trust: --drop-status retires verdicts left by a
        # superseded check (e.g. goci's old INVALID_TOKEN).
        if entry.get("api_status") in drop_statuses:
            return False
        return bool(entry.get("final_validation"))

    kept = {k: v for k, v in db.items() if keep(v)}
    dropped = len(db) - len(kept)

    if not dry_run and dropped:
        shutil.copy2(db_path, db_path + ".prune-backup")
        with open(db_path, "w", encoding="utf-8") as fh:
            json.dump(kept, fh, ensure_ascii=False, indent=2)

    return len(db), len(kept), dropped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="+", help="directories to search for validated_secrets_db.json")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--drop-status", action="append", default=[],
                    help="also drop entries with this api_status even if they validated real "
                         "(repeatable; for retiring verdicts from a superseded validator)")
    args = ap.parse_args()

    total_before = total_kept = total_dropped = 0
    found = 0
    for root in args.roots:
        for dirpath, _, filenames in os.walk(root):
            if "validated_secrets_db.json" not in filenames:
                continue
            found += 1
            db_path = os.path.join(dirpath, "validated_secrets_db.json")
            before, kept, dropped = prune(db_path, args.dry_run, set(args.drop_status))
            total_before += before
            total_kept += kept
            total_dropped += dropped
            print(f"{db_path}: {before} -> {kept} (dropped {dropped})")

    if not found:
        print("No validated_secrets_db.json found", file=sys.stderr)
        return 1

    verb = "would drop" if args.dry_run else "dropped"
    print(f"\n{found} databases: {total_before} entries, kept {total_kept} real, {verb} {total_dropped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
