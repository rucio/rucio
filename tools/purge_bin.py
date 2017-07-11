#!/usr/bin/env python

from rucio.db.sqla.session import get_session

# Exit statuses
OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3


def purge_bin():
    try:
        session = get_session()
        sql = "select table_name from user_tables"
        for table in session.execute(sql):
            query = "drop table %s cascade constraints purge" % table[0]
            session.execute(query)
    except:
        pass
    finally:
        session.remove()


if __name__ == "__main__":
    purge_bin()
