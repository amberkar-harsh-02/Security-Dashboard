"""Manage analyst accounts.

    python manage.py list-users
    python manage.py create-user <username>
    python manage.py set-password <username>

Passwords are read from the terminal without echo.
"""

import argparse
import getpass
import sqlite3
import sys

from siem import db
from siem.auth import create_user, list_usernames, set_password
from siem.config import Config


def _ask_password():
    first = getpass.getpass("New password: ")
    if first != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    return first


def main():
    parser = argparse.ArgumentParser(description="Manage SIEM analyst accounts.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-users", help="Show all analyst accounts")
    create = commands.add_parser("create-user", help="Add an analyst account")
    create.add_argument("username")
    reset = commands.add_parser("set-password", help="Change an analyst's password")
    reset.add_argument("username")
    args = parser.parse_args()

    config = Config()
    db.init_schema(config.DB_PATH)
    conn = db.connect(config.DB_PATH)
    try:
        if args.command == "list-users":
            for name in list_usernames(conn):
                print(name)
        elif args.command == "create-user":
            create_user(conn, args.username, _ask_password())
            print(f"Created {args.username}.")
        else:
            set_password(conn, args.username, _ask_password())
            print(f"Password changed for {args.username}.")
    except ValueError as exc:
        sys.exit(str(exc))
    except KeyError:
        sys.exit(f"No analyst named {args.username!r}.")
    except sqlite3.IntegrityError:
        sys.exit(f"An analyst named {args.username!r} already exists.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
