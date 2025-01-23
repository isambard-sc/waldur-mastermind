import collections

Account = collections.namedtuple("Account", ["name", "description", "organization"])
Association = collections.namedtuple("Association", ["account", "user", "value"])

class Quotas:
    def __init__(self, node=0):
        self.node = node

    def __add__(self, other):
        return Quotas(
            self.node + other.node,
        )

    def __str__(self):
        return f"Quotas: NODE={self.node}"

    def __repr__(self) -> str:
        return self.__str__()
