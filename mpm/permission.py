#  Copyright (C) 2023 Roderik Ploszek
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

from enum import IntFlag, _power_of_two


# BetterFlag is from https://stackoverflow.com/a/66465125/4739767
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

    def short_repr(self) -> str:
        return ''.join(
            m.name[0]
            for m in self.__class__
            if m.value & self.value and _power_of_two(m.value)
        )


class Permission(BetterIntFlag):
    READ = 1
    WRITE = 2
    SEE = 4
