"""Ops CLI for issuing/managing customer onboarding links.

Stdlib-only, mirrors mock_dashboard.py's "no extra install needed" philosophy.
This is how Brian (or whoever runs Aman's ops side) hands a new customer their
one-time setup link -- there's no self-serve signup in this POC's scope.

    python3 onboarding_cli.py generate --tenant-id tenant-456 --label "Acme Corp"
    python3 onboarding_cli.py list
    python3 onboarding_cli.py revoke <token>
"""

from __future__ import annotations

import argparse

from onboarding_store import TokenError, generate_token, list_tokens, revoke_token

FRONTEND_BASE_URL = "http://localhost:5173/onboard"


def cmd_generate(args: argparse.Namespace) -> None:
    token = generate_token(args.tenant_id, label=args.label, expires_days=args.expires_days)
    print(f"Onboarding link for {args.tenant_id!r}:")
    print(f"  {FRONTEND_BASE_URL}/{token}")
    print(f"  (expires in {args.expires_days} days, single-use)")


def cmd_list(_args: argparse.Namespace) -> None:
    records = list_tokens()
    if not records:
        print("No onboarding tokens issued yet.")
        return
    for token, record in records.items():
        print(f"{token}  tenant={record['tenant_id']!r}  status={record['status']}  label={record['label']!r}")


def cmd_revoke(args: argparse.Namespace) -> None:
    try:
        revoke_token(args.token)
    except TokenError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1) from exc
    print(f"Revoked {args.token}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate", help="Issue a new onboarding link")
    generate_parser.add_argument("--tenant-id", required=True)
    generate_parser.add_argument("--label", default="")
    generate_parser.add_argument("--expires-days", type=int, default=30)
    generate_parser.set_defaults(func=cmd_generate)

    list_parser = subparsers.add_parser("list", help="List all issued onboarding tokens")
    list_parser.set_defaults(func=cmd_list)

    revoke_parser = subparsers.add_parser("revoke", help="Revoke an onboarding token")
    revoke_parser.add_argument("token")
    revoke_parser.set_defaults(func=cmd_revoke)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
