"""
    Helpers that do not belong anywhere else
"""

import sqlite3

def groupwiseIterator(iterable, n):
    """ return iterator that yields iterator that yields at most n values of it

    list(map(list,groupwiseIterator(range(5),2))) ->[[0,1],[2,3],[4]]
    """
    it = iter(iterable)
    r = range(1, n)

    def subIt(first):
        yield first
        for i in r:
            yield next(it)
    # take the first of every n elements out here, give it to subIt to yield it
    for first in it:
        yield subIt(first)


def addAttribute(attr, val):
    """
        An anotation that adds an attribute, for example:

        @addAttribute("paramType",int)
        def a(x):
            ...

        a.paramType == int
    """
    def deco(func):
        setattr(func, attr, val)
        return func
    return deco


class CommonDatabase:

    """ Basic Wrapper for SQLite Database """

    def __init__(self, databasefile):
        self.db = sqlite3.connect(
            str(databasefile),
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        self.db.row_factory = sqlite3.Row

        self.cursor = self.db.cursor
        self.commit = self.db.commit

    def __enter__(self, *args):
        return self.db.__enter__(*args)

    def __exit__(self, *args):
        return self.db.__exit__(*args)

    def close(self):
        self.db.close()

    def setSetting(self, key, value):
        """ Sets a setting"""
        cur = self.db.cursor()
        try:
            with self.db:
                cur.execute("""
                    INSERT OR REPLACE INTO
                        setting (key,value)
                    VALUES
                        (?,?)""",
                            (key, value))
        finally:
            cur.close()

    def getSettingDef(self, key, default):
        try:
            return self.getSetting(key)
        except KeyError:
            return default

    def getSetting(self, key):
        cur = self.db.cursor()
        try:
            cur.execute(
                "SELECT value FROM setting WHERE key = :key", {"key": key})
            r = cur.fetchall()
            if len(r) == 1:
                return r[0]['value']
            assert len(r) == 0
        finally:
            cur.close()
        raise KeyError("No Setting: " + key)

    def createDatabase(self):
        with self.db:
            self.db.executescript("""
                CREATE TABLE setting (
                    key STRING PRIMARY KEY,
                    value STRING
                );
                """)


def fileSizeFormat(s):
    x = 1
    for m in 'B', 'KB', 'MB', 'GB', 'TB':
        if s < 2000 * x:
            return "%d%s" % (s // x, m)
        x = x * 1024
