import unittest
import generalize


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


if __name__ == '__main__':
    unittest.main()
