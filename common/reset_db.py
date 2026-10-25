"""Empty every table in ghostkey.db. Run inside a container: python -m common.reset_db"""
from __future__ import annotations

from common import db


def main() -> None:
    conn = db.connect()
    db.init(conn)
    db.reset(conn)
    conn.close()
    print("ghostkey.db emptied")


if __name__ == "__main__":
    main()
