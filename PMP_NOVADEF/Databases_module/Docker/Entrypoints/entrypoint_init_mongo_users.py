#!/usr/bin/env python3
"""
Idempotently creates the per-database least-privilege MongoDB users on top of
the root user. Run once at startup by the init-mongo-users container.
"""

import os
import sys

from pymongo import MongoClient
from pymongo.errors import OperationFailure


def ensure_user(admin_db, username: str, password: str, role: str, database: str) -> None:
    """Create `username` scoped to `role` on `database` unless it already exists."""
    if admin_db.command("usersInfo", username)["users"]:
        print(f"{username} already exists, skipping.")
        return
    admin_db.command(
        "createUser",
        username,
        pwd=password,
        roles=[{"role": role, "db": database}],
    )
    print(f"Created user {username}.")


def main() -> int:
    client = MongoClient(
        host="mongodb",
        port=int(os.environ.get("MONGO_PORT", "27017")),
        username=os.environ["MONGO_INITDB_ROOT_USERNAME"],
        password=os.environ["MONGO_INITDB_ROOT_PASSWORD"],
        authSource="admin",
    )
    admin_db = client["admin"]

    try:
        ensure_user(
            admin_db,
            os.environ["MONGO_SNORT_USER_NAME"],
            os.environ["MONGO_SNORT_USER_PASSWORD"],
            role="readWrite",
            database="snort_db",
        )
        ensure_user(
            admin_db,
            os.environ["MONGO_FLOW_WRITER_NAME"],
            os.environ["MONGO_FLOW_WRITER_PASSWORD"],
            role="readWrite",
            database="flow_db",
        )
        ensure_user(
            admin_db,
            os.environ["MONGO_FLOW_READER_NAME"],
            os.environ["MONGO_FLOW_READER_PASSWORD"],
            role="read",
            database="flow_db",
        )
    except OperationFailure as exc:
        print(f"Failed to create MongoDB role users: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
