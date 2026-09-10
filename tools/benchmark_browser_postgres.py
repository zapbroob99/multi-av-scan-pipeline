"""Destructive, disposable PostgreSQL acceptance for bounded browser read models.

The database name must end in ``_test`` or ``_acceptance`` and the server must be
loopback. The public schema is dropped only with the explicit confirmation flag.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import statistics
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import database as db
from app.models import StoredSample
from app.services import archive_read, batch_read, dashboard_read, scan_management, scan_report_read


def percentile(values: list[float], percent: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int((len(ordered) - 1) * percent)))]


def measure(action, iterations: int) -> dict[str, float]:
    durations = []
    for _ in range(iterations):
        started = time.perf_counter()
        action()
        durations.append((time.perf_counter() - started) * 1000)
    return {'median_ms': round(statistics.median(durations), 3),
            'p95_ms': round(percentile(durations, .95), 3),
            'max_ms': round(max(durations), 3)}


def require_disposable(url: str, confirmed: bool) -> None:
    parsed = urlsplit(url)
    database = parsed.path.lstrip('/')
    if not confirmed:
        raise SystemExit('Refusing to reset PostgreSQL without --confirm-reset-public-schema.')
    if parsed.hostname not in {'127.0.0.1', 'localhost', '::1'}:
        raise SystemExit('Refusing non-loopback PostgreSQL. Use a local disposable server.')
    if not database.endswith(('_test', '_acceptance')):
        raise SystemExit("Refusing database whose name does not end in '_test' or '_acceptance'.")


def plan(connection, query: str, params: tuple[object, ...]) -> dict[str, object]:
    row = connection.execute('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' + query, params).fetchone()
    root = row['QUERY PLAN'][0]
    nodes: list[str] = []
    indexes: list[str] = []
    def visit(node):
        nodes.append(str(node.get('Node Type')))
        if node.get('Index Name'):
            indexes.append(str(node['Index Name']))
        for child in node.get('Plans', []):
            visit(child)
    visit(root['Plan'])
    return {'execution_ms': round(float(root['Execution Time']), 3),
            'planning_ms': round(float(root['Planning Time']), 3),
            'nodes': nodes, 'indexes': sorted(set(indexes)),
            'shared_hit_blocks': root['Plan'].get('Shared Hit Blocks', 0),
            'shared_read_blocks': root['Plan'].get('Shared Read Blocks', 0)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database-url', default=os.getenv('MASP_TEST_POSTGRES_URL', ''))
    parser.add_argument('--confirm-reset-public-schema', action='store_true')
    parser.add_argument('--rows', type=int, default=100000)
    parser.add_argument('--archive-rows', type=int, default=100000)
    parser.add_argument('--iterations', type=int, default=15)
    parser.add_argument('--concurrency', type=int, default=8)
    parser.add_argument('--max-latest-p95-ms', type=float, default=100)
    parser.add_argument('--max-deep-p95-ms', type=float, default=100)
    parser.add_argument('--max-search-p95-ms', type=float, default=1500)
    parser.add_argument('--max-summary-p95-ms', type=float, default=500)
    parser.add_argument('--max-archive-p95-ms', type=float, default=100)
    parser.add_argument('--max-archive-search-p95-ms', type=float, default=1500)
    parser.add_argument('--max-batch-p95-ms', type=float, default=100)
    parser.add_argument('--max-concurrent-p95-ms', type=float, default=1000)
    parser.add_argument('--output')
    args = parser.parse_args()
    if not args.database_url:
        parser.error('--database-url or MASP_TEST_POSTGRES_URL is required')
    if not 1000 <= args.rows <= 2000000 or not 1000 <= args.archive_rows <= 2000000:
        parser.error('--rows and --archive-rows must be between 1000 and 2000000')
    if not 3 <= args.iterations <= 100 or not 1 <= args.concurrency <= 32:
        parser.error('--iterations must be 3..100 and --concurrency 1..32')
    require_disposable(args.database_url, args.confirm_reset_public_schema)
    original = (db.DATABASE_URL, db.DB_POOL_ENABLED, db.DB_POOL_MIN, db.DB_POOL_MAX)
    db.close_pool()
    try:
        db.DATABASE_URL, db.DB_POOL_ENABLED = args.database_url, False
        import psycopg
        with psycopg.connect(args.database_url, autocommit=True) as connection:
            connection.execute('DROP SCHEMA IF EXISTS public CASCADE')
            connection.execute('CREATE SCHEMA public')
        db.init_db()
        engine_id = db.create_engine_instance('static_metadata', 'Benchmark Metadata')
        sample = db.create_sample(StoredSample('synthetic.bin', 'absent', 'absent',
            'application/octet-stream', 1024, 'a' * 32, 'b' * 40, 'c' * 64))
        batch = db.create_scan_batch(source='manual', original_filename='benchmark.zip', archive_mode='lazy_extract_on_detection')
        parent = db.create_scan_job(sample, 'Archive benchmark', 'Normal', '', batch_id=batch,
                                    scan_role='container', status='completed', verdict='info', risk_score=0)
        with db.connect() as connection:
            connection.execute('''INSERT INTO scan_jobs
                (sample_id, case_name, priority, note, source, scan_role, status, verdict, risk_score)
                SELECT ?, 'Case ' || g, 'Normal', CASE WHEN g %% 997 = 0 THEN 'rare-token' ELSE '' END,
                    'manual', 'standalone', CASE WHEN g %% 10 = 0 THEN 'running' ELSE 'completed' END,
                    CASE WHEN g %% 20 = 0 THEN 'high' ELSE 'info' END, CASE WHEN g %% 10 = 0 THEN NULL ELSE 0 END
                FROM generate_series(1, ?) AS g''', (sample, args.rows))
            connection.execute('''INSERT INTO scan_jobs
                (sample_id, batch_id, parent_scan_id, case_name, priority, note, source,
                 relative_path, scan_role, status, verdict, risk_score)
                SELECT ?, ?, ?, 'Archive', 'Normal', '', 'manual', 'pack/member-' || g || '.bin',
                    'child', CASE WHEN g %% 10 = 0 THEN 'running' ELSE 'completed' END, 'info', 0
                FROM generate_series(1, ?) AS g''', (sample, batch, parent, args.archive_rows))
            connection.execute('ANALYZE samples')
            connection.execute('ANALYZE scan_jobs')
            deep_before = connection.execute("SELECT id FROM scan_jobs WHERE source='manual' AND scan_role != 'child' ORDER BY id DESC OFFSET ? LIMIT 1",
                                             (int(args.rows * .9),)).fetchone()['id']
            deep_after = connection.execute("SELECT id FROM scan_jobs WHERE parent_scan_id = ? ORDER BY id ASC OFFSET ? LIMIT 1",
                                             (parent, int(args.archive_rows * .9))).fetchone()['id']
            deep_batch_cursor = connection.execute('''SELECT created_at, id FROM scan_jobs
                WHERE batch_id = ? ORDER BY created_at ASC, id ASC OFFSET ? LIMIT 1''',
                (batch, int(args.archive_rows * .9))).fetchone()
        db.DB_POOL_ENABLED, db.DB_POOL_MIN, db.DB_POOL_MAX = True, 0, max(args.concurrency, 4)
        dashboard_read._summary_cache = None
        latest = lambda: dashboard_read.scan_page(limit=20, before=None, query='', status='all', risk='all')
        deep = lambda: dashboard_read.scan_page(limit=20, before=deep_before, query='', status='all', risk='all')
        search = lambda: dashboard_read.scan_page(limit=20, before=None, query='not-present-anywhere', status='all', risk='all')
        archive = lambda: archive_read.children(parent, limit=20, after=deep_after, attempt=0, query='', status='all')
        archive_search = lambda: archive_read.children(parent, limit=20, after=None, attempt=None, query='not-present-anywhere', status='all')
        batch_page = lambda: batch_read.page(batch, limit=20, after_id=deep_batch_cursor['id'],
                                             after_created=str(deep_batch_cursor['created_at']))
        cold_summary = lambda: (setattr(dashboard_read, '_summary_cache', None), dashboard_read.summary())[1]
        latest(); deep(); search(); archive(); archive_search(); batch_page(); cold_summary()
        timings = {'latest_20': measure(latest, args.iterations),
                   'deep_keyset_20': measure(deep, args.iterations),
                   'substring_no_match': measure(search, args.iterations),
                   'summary_uncached': measure(cold_summary, args.iterations),
                   'archive_deep_keyset_20': measure(archive, args.iterations),
                   'archive_substring_no_match': measure(archive_search, args.iterations),
                   'batch_deep_keyset_20': measure(batch_page, args.iterations),
                   'report': measure(lambda: scan_report_read.report(parent), args.iterations),
                   'summary_export_json': measure(lambda: scan_management.summary_export(parent, 'json'), args.iterations),
                   'full_export_json': measure(lambda: scan_management.full_export(parent, 'json'), args.iterations)}
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            def timed(action):
                one = time.perf_counter()
                action()
                return (time.perf_counter() - one) * 1000
            started = time.perf_counter()
            mixed_actions = (latest, search, batch_page)
            futures = [pool.submit(timed, mixed_actions[i % len(mixed_actions)]) for i in range(args.concurrency * 4)]
            durations = [future.result() for future in futures]
            wall_ms = (time.perf_counter() - started) * 1000
        timings['mixed_concurrent'] = {'median_ms': round(statistics.median(durations), 3),
                                       'p95_ms': round(percentile(durations, .95), 3),
                                       'max_ms': round(max(durations), 3), 'wall_ms': round(wall_ms, 3)}
        with db.connect() as connection:
            from app.services.browser_db_budget import apply_read_budget
            apply_read_budget(connection)
            presence_sql, presence_params = archive_read.child_presence_statement(
                [{'id': deep_after + offset, 'child_batch_id': batch} for offset in range(1, 22)])
            plans = {
                'latest_20': plan(connection, '''SELECT j.id FROM scan_jobs j JOIN samples s ON s.id=j.sample_id
                    WHERE j.source='manual' AND j.scan_role != 'child' ORDER BY j.id DESC LIMIT ?''', (21,)),
                'deep_keyset_20': plan(connection, '''SELECT j.id FROM scan_jobs j JOIN samples s ON s.id=j.sample_id
                    WHERE j.source='manual' AND j.scan_role != 'child' AND j.id < ? ORDER BY j.id DESC LIMIT ?''', (deep_before, 21)),
                'substring_no_match': plan(connection, '''SELECT j.id FROM scan_jobs j JOIN samples s ON s.id=j.sample_id
                    WHERE j.source='manual' AND j.scan_role != 'child' AND
                    (LOWER(s.original_filename) LIKE ? OR LOWER(s.sha256) LIKE ? OR LOWER(s.sha1) LIKE ? OR LOWER(s.md5) LIKE ?
                     OR LOWER(j.case_name) LIKE ? OR LOWER(j.note) LIKE ? OR LOWER(j.priority) LIKE ?)
                    ORDER BY j.id DESC LIMIT ?''', tuple(['%not-present-anywhere%'] * 7 + [21])),
                'archive_deep_keyset_20': plan(connection, '''SELECT c.id FROM scan_jobs c JOIN samples s ON s.id=c.sample_id
                    WHERE c.parent_scan_id=? AND c.source='manual' AND c.scan_role='child' AND c.batch_id=? AND c.id>?
                    ORDER BY c.id ASC LIMIT ?''', (parent, batch, deep_after, 21)),
                'archive_child_presence_21': plan(connection, presence_sql, presence_params),
                'batch_deep_keyset_20': plan(connection, '''SELECT j.id FROM scan_jobs j JOIN samples s ON s.id=j.sample_id
                    WHERE j.batch_id=? AND j.source='manual' AND (j.created_at, j.id) > (?, ?)
                    ORDER BY j.created_at ASC, j.id ASC LIMIT ?''',
                    (batch, deep_batch_cursor['created_at'], deep_batch_cursor['id'], 21)),
            }
        budgets = {'latest_20': args.max_latest_p95_ms, 'deep_keyset_20': args.max_deep_p95_ms,
                   'substring_no_match': args.max_search_p95_ms, 'summary_uncached': args.max_summary_p95_ms,
                   'archive_deep_keyset_20': args.max_archive_p95_ms,
                   'archive_substring_no_match': args.max_archive_search_p95_ms,
                   'batch_deep_keyset_20': args.max_batch_p95_ms,
                   'mixed_concurrent': args.max_concurrent_p95_ms}
        failures = {name: {'observed_p95_ms': timings[name]['p95_ms'], 'budget_ms': budget}
                    for name, budget in budgets.items() if timings[name]['p95_ms'] > budget}
        report = {'backend': 'disposable PostgreSQL', 'postgres_version': None, 'rows': args.rows,
                  'archive_rows': args.archive_rows, 'iterations': args.iterations,
                  'concurrency': args.concurrency, 'timings': timings, 'plans': plans,
                  'budgets_ms': budgets, 'failures': failures,
                  'limitations': ['Loopback single-host synthetic data', 'Warm cache after setup',
                                  'No HTTP/TLS/proxy latency', 'No worker write load']}
        with db.connect() as connection:
            report['postgres_version'] = connection.execute('SHOW server_version').fetchone()['server_version']
        rendered = json.dumps(report, indent=2)
        print(rendered)
        if args.output:
            Path(args.output).write_text(rendered + '\n', encoding='utf-8')
        return 1 if failures else 0
    finally:
        dashboard_read._summary_cache = None
        db.close_pool()
        db.DATABASE_URL, db.DB_POOL_ENABLED, db.DB_POOL_MIN, db.DB_POOL_MAX = original


if __name__ == '__main__':
    raise SystemExit(main())
