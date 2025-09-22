"""Command line interface for the password vault."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Callable

from .vault import Entry, Vault, VaultError, VaultLockedError


def prompt_new_master_password() -> str:
    first = getpass.getpass("Enter a new master password: ")
    second = getpass.getpass("Confirm the new master password: ")
    if not first:
        raise ValueError("Master password cannot be empty")
    if first != second:
        raise ValueError("Passwords do not match")
    return first


def prompt_master_password() -> str:
    password = getpass.getpass("Master password: ")
    if not password:
        raise ValueError("Master password cannot be empty")
    return password


def prompt_entry_password() -> str:
    password = getpass.getpass("Entry password: ")
    if not password:
        raise ValueError("Entry password cannot be empty")
    return password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage an encrypted password vault")
    parser.add_argument("vault", help="Path to the vault file")

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a new vault")
    init_parser.add_argument("--overwrite", action="store_true", help="Overwrite existing vault")
    init_parser.set_defaults(func=handle_init)

    list_parser = subparsers.add_parser("list", help="List stored entries")
    list_parser.set_defaults(func=handle_list)

    add_parser = subparsers.add_parser("add", help="Add or update an entry")
    add_parser.add_argument("name", help="Name of the entry")
    add_parser.add_argument("--username", required=True, help="Username for the entry")
    add_parser.add_argument("--password", help="Password value; prompted if omitted")
    add_parser.add_argument("--url", help="Related URL", default=None)
    add_parser.add_argument("--notes", help="Additional notes", default=None)
    add_parser.add_argument("--overwrite", action="store_true", help="Allow updating existing entries")
    add_parser.set_defaults(func=handle_add)

    show_parser = subparsers.add_parser("show", help="Display an entry")
    show_parser.add_argument("name", help="Name of the entry")
    show_parser.set_defaults(func=handle_show)

    remove_parser = subparsers.add_parser("remove", help="Delete an entry")
    remove_parser.add_argument("name", help="Name of the entry")
    remove_parser.add_argument("--force", action="store_true", help="Do not ask for confirmation")
    remove_parser.set_defaults(func=handle_remove)

    return parser


def handle_init(args: argparse.Namespace) -> None:
    vault = Vault(Path(args.vault))
    try:
        password = prompt_new_master_password()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    try:
        vault.initialize(password, overwrite=args.overwrite)
    except FileExistsError:
        print("Vault already exists. Use --overwrite to replace it.", file=sys.stderr)
        raise SystemExit(1)
    else:
        print(f"Vault created at {vault.path}")


def handle_list(args: argparse.Namespace) -> None:
    vault = Vault(Path(args.vault))
    master_password = _prompt_password_with_exit()
    try:
        entries = vault.list_entries(master_password)
    except (VaultError, VaultLockedError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    if not entries:
        print("Vault is empty")
    else:
        for name in entries:
            print(name)


def handle_add(args: argparse.Namespace) -> None:
    vault = Vault(Path(args.vault))
    master_password = _prompt_password_with_exit()

    entry_password = args.password
    if entry_password is None:
        try:
            entry_password = prompt_entry_password()
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1)

    try:
        vault.add_entry(
            master_password,
            args.name,
            username=args.username,
            password=entry_password,
            url=args.url,
            notes=args.notes,
            overwrite=args.overwrite,
        )
    except (VaultError, VaultLockedError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    else:
        print(f"Entry '{args.name}' saved")


def handle_show(args: argparse.Namespace) -> None:
    vault = Vault(Path(args.vault))
    master_password = _prompt_password_with_exit()

    try:
        entry = vault.get_entry(master_password, args.name)
    except (VaultError, VaultLockedError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    _print_entry(entry)


def handle_remove(args: argparse.Namespace) -> None:
    vault = Vault(Path(args.vault))
    master_password = _prompt_password_with_exit()

    if not args.force:
        confirmation = input(f"Delete entry '{args.name}'? [y/N]: ").strip().lower()
        if confirmation not in {"y", "yes"}:
            print("Aborted")
            return

    try:
        vault.remove_entry(master_password, args.name)
    except (VaultError, VaultLockedError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    else:
        print(f"Entry '{args.name}' removed")


def _prompt_password_with_exit() -> str:
    try:
        return prompt_master_password()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)


def _print_entry(entry: Entry) -> None:
    print(f"Name: {entry.name}")
    print(f"Username: {entry.username}")
    print(f"Password: {entry.password}")
    if entry.url:
        print(f"URL: {entry.url}")
    if entry.notes:
        print(f"Notes: {entry.notes}")
    if entry.created_at:
        print(f"Created: {entry.created_at.isoformat()}")
    if entry.updated_at:
        print(f"Updated: {entry.updated_at.isoformat()}")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    func: Callable[[argparse.Namespace], None] = getattr(args, "func")
    func(args)


if __name__ == "__main__":  # pragma: no cover
    main()
