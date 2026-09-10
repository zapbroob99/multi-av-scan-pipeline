"""Disposable SQLite read-model benchmark, not a PostgreSQL capacity claim."""
import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import database as db
from app.models import StoredSample
from app.services import dashboard_read


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows', type=int, default=100000)
    args = parser.parse_args()
    if not 100 <= args.rows <= 1000000:
        parser.error('--rows must be between 100 and 1000000')
    original = (db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED)
    db.close_pool()
    try:
        with tempfile.TemporaryDirectory(prefix='masp-dashboard-bench-', ignore_cleanup_errors=True) as directory:
            db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = Path(directory) / 'benchmark.db', '', False
            db.init_db()
            sample = db.create_sample(StoredSample('synthetic.bin', 'absent', 'absent',
                'application/octet-stream', 1024, 'a' * 32, 'b' * 40, 'c' * 64))
            with db.connect() as connection:
                connection.executemany('''INSERT INTO scan_jobs
                    (sample_id, case_name, priority, note, status, verdict, source, scan_role)
                    VALUES (?, ?, 'normal', '', ?, ?, 'manual', 'standalone')''',
                    ((sample, f'Case {index}', 'running' if index % 10 == 0 else 'completed',
                      'high' if index % 20 == 0 else 'info') for index in range(args.rows)))

            def page(before=None, query=''):
                return dashboard_read.scan_page(limit=20, before=before, query=query, status='all', risk='all')

            def cold_summary():
                dashboard_read._summary_cache = None
                return dashboard_read.summary()

            def measure(action):
                durations = []
                for _ in range(7):
                    started = time.perf_counter()
                    action()
                    durations.append((time.perf_counter() - started) * 1000)
                return round(statistics.median(durations), 3)

            report = {'backend': 'disposable SQLite', 'rows': args.rows, 'iterations': 7, 'median_ms': {
                'latest_20': measure(page),
                'seek_90_percent_deep_20': measure(lambda: page(before=args.rows // 10)),
                'substring_no_match': measure(lambda: page(query='not-present-anywhere')),
                'summary_uncached': measure(cold_summary),
                'summary_cached': measure(dashboard_read.summary),
            }, 'page_json_bytes': len(page().model_dump_json().encode())}
            print(json.dumps(report, indent=2))
    finally:
        dashboard_read._summary_cache = None
        db.DB_PATH, db.DATABASE_URL, db.DB_POOL_ENABLED = original


if __name__ == '__main__':
    main()
