"""
    Permission constants used in share groups
"""

from enum import Enum, unique


class Permission(Enum):
    ADD_ITEMS = 1
    WRITE_ITEMS = 2
    READ_ITEMS = 4

    LIST_MEMBERS = 8

    REMOVE_ITEMS = 16

    def __lt__(self, other):
        return self.name <= other.name

    def __equal__(self, other):
        return self.name == other.name


class PermissionSet:

    def __init__(self, *perms):
        s = set()
        for p in perms:
            if p not in Permission:
                p = Permission[p]
            s.add(p)
        self.permissions = frozenset(s)

    def hasAll(self, *testPerms):
        for p in testPerms:
            assert p in Permission
            if not p in self.permissions:
                return False
        return True

    def __contains__(self, p):
        assert p in Permission
        return p in self.permissions

    def __iter__(self):
        yield from self.permissions

    def __repr__(self):
        return "[" + ", ".join(p.name for p in sorted(self.permissions)) + "]"

    # can be stored as bit mask
    @classmethod
    def fromMask(cls, mask):
        r = set()
        if mask is not None:
            for p in Permission:
                if mask & p.value:
                    r.add(p)
        return cls(*r)

    def toMask(self):
        m = 0
        for p in self:
            m |= p.value
        return m

PermissionSet.ALL = PermissionSet(*[p for p in Permission])


for p in Permission:
    globals()[p.name] = p
