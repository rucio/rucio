#!/usr/bin/env python

from rucio.db.sqla.session import get_session

# Exit statuses
OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3


def purge_bin():
    try:
        session = get_session()
        sql = "PURGE RECYCLEBIN"
        session.execute(sql).fetchall()
    except:
        pass
    finally:
        session.remove()

if __name__ == "__main__":
    purge_bin()
