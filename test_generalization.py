import unittest
from generalize import generalize, runs


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
            runs._get_numeric_regexp('123something123'),
            r'\d*something\d*'
        )

    def test2(self):
        self.assertEqual(
            runs._get_numeric_regexp('123some1thing123'),
            r'\d*some\d*thing\d*'
        )

    def test3(self):
        self.assertEqual(
            runs._get_numeric_regexp('a1b2c'),
            r'a\d*b\d*c'
        )

    def test4(self):
        self.assertEqual(
            runs._get_numeric_regexp('hello world'),
            'hello world'
        )


if __name__ == '__main__':
    unittest.main()
