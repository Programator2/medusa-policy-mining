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

import unittest
from mpm.generalize import generalize, runs, lcs


class TestProcGeneralization(unittest.TestCase):
    def test_positive(self):
        self.assertEqual(
            generalize.generalize_proc('/proc/190/longer/path'),
            '/proc/[0-9]+/longer/path',
        )

    def test_negative(self):
        self.assertEqual(
            generalize.generalize_proc('/etc/proc/190/longer/path'),
            '/etc/proc/190/longer/path',
        )


class TestNumericRegexp(unittest.TestCase):
    def test1(self):
        self.assertEqual(
            runs._get_numeric_regexp('123something123'), r'\d*something\d*'
        )

    def test2(self):
        self.assertEqual(
            runs._get_numeric_regexp('123some1thing123'), r'\d*some\d*thing\d*'
        )

    def test3(self):
        self.assertEqual(runs._get_numeric_regexp('a1b2c'), r'a\d*b\d*c')

    def test4(self):
        self.assertEqual(
            runs._get_numeric_regexp('hello world'), 'hello\ world'
        )


class TestPrefixPostfixRegexp(unittest.TestCase):
    def test_both(self):
        inp = [
            '/usr/sbin/postconfx',
            '/usr/sbin/semndmail.postfix',
            '/usr/sbin/postsuperx',
            '/usr/sbin/postlogx',
        ]
        self.assertEqual(
            lcs.prefix_postfix_regexp(inp), r'/usr/sbin/.*?post.*?x'
        )

    def test_just_prefix(self):
        inp = [
            '/usr/sbin/postconf',
            '/usr/sbin/semndmail.postfix',
            '/usr/sbin/postsuper',
            '/usr/sbin/postlog',
        ]
        self.assertEqual(
            lcs.prefix_postfix_regexp(inp), r'/usr/sbin/.*?post.*?'
        )


if __name__ == '__main__':
    unittest.main()
