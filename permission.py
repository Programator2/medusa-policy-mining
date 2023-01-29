# https://stackoverflow.com/a/66465125/4739767
from enum import IntFlag, _power_of_two


class BetterIntFlag(IntFlag):
    def __repr__(self):
        if self.value == 0:
            return "%s(0)" % self.__class__.__name__
        return '|'.join(
            m.name
            for m in self.__class__
            if m.value & self.value and _power_of_two(m.value)
        )

    __str__ = __repr__


class Permission(BetterIntFlag):
    READ = 1
    WRITE = 2
    SEE = 4
