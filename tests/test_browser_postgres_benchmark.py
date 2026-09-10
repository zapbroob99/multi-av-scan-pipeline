import unittest

from tools.benchmark_browser_postgres import percentile, require_disposable


class BrowserPostgresBenchmarkSafetyTests(unittest.TestCase):
    def test_requires_confirmation_loopback_and_disposable_database_name(self):
        safe = 'postgresql://user:secret@127.0.0.1:5432/browser_acceptance'
        require_disposable(safe, True)
        for url, confirmed in (
            (safe, False),
            ('postgresql://user:secret@db.internal:5432/browser_acceptance', True),
            ('postgresql://user:secret@127.0.0.1:5432/masp', True),
        ):
            with self.assertRaises(SystemExit):
                require_disposable(url, confirmed)

    def test_percentile_is_deterministic_for_small_samples(self):
        values = [10.0, 1.0, 4.0, 8.0, 2.0]
        self.assertEqual(percentile(values, .5), 4.0)
        self.assertEqual(percentile(values, .95), 8.0)


if __name__ == '__main__':
    unittest.main()
