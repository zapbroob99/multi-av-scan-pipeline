"""Isolated browser acceptance backend: never imports app.main or opens MASP data."""
from pathlib import Path
import sys
import tempfile
import os

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI
import uvicorn
from app import database as db
from app.models import StoredSample, EngineResultInput
from app.services import auth
from app.services import ingest, cleanup, sample_paths
from app.services.ui_api import router


def main():
    with tempfile.TemporaryDirectory(prefix="masp-console-e2e-", ignore_cleanup_errors=True) as directory:
        db.close_pool()
        db.DATABASE_URL = ""
        db.DB_POOL_ENABLED = False
        db.DB_PATH = Path(directory) / "console.db"
        ingest.SAMPLES_DIR = Path(directory) / "samples"
        cleanup.SAMPLES_DIR = sample_paths.SAMPLES_DIR = ingest.SAMPLES_DIR
        db.init_db()
        db.create_user("console-admin", auth.hash_password("console-test-only"), "admin")
        db.create_user("console-analyst", auth.hash_password("console-test-only"), "analyst")
        db.create_user("account-analyst", auth.hash_password("console-test-only"), "analyst")
        db.create_user("managed-analyst", auth.hash_password("console-test-only"), "analyst")
        db.create_engine_instance("static_metadata", "Static Metadata")
        # Offline synthetic node: never starts a real worker or advertises health.
        db.upsert_worker_node_heartbeat(node_id='console-node', display_name='Acceptance worker',
            hostname='fixture-host', platform='windows', agent_version='fixture', labels_json='{"site":"lab"}',
            capacity=2, advertised_engine_keys_json='["microsoft_defender"]', runtime_state='idle',
            active_scan_id=None, process_id=0, last_heartbeat_at=1)
        db.create_worker_agent_credential(node_id='console-node', token_hash='fixture-only-unusable-hash', token_prefix='fixture')
        # Metadata only: no real sample files, adapters or scan workers are run.
        for index in range(25):
            sample_id = db.create_sample(StoredSample(f"acceptance-{index:02}.bin", f"fixture-{index}",
                str(Path(directory) / f"absent-{index}"), "application/octet-stream", 4096,
                f"{index:032x}", f"{index:040x}", f"{index:064x}"))
            terminal = index in {22, 24}
            scan_id = db.create_scan_job(sample_id, "Browser acceptance", "normal", "",
                status="failed" if index == 24 else "completed" if terminal else "queued",
                verdict="info" if terminal else "pending", risk_score=0 if terminal else None)
            if index == 24:
                db.create_engine_result(scan_id, EngineResultInput('Static Metadata', 'failed', False, 'info', 0, None,
                    '<script>benign fixture text</script>', 12, error_message='Synthetic worker failure',
                    details_json='{"marker":"' + 'x' * 17000 + 'FULL_OUTPUT_END"}'))
        batch = db.create_scan_batch(source='manual', original_filename='outer.zip', archive_mode='lazy_extract_on_detection')
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET batch_id = ?, scan_role = 'container' WHERE id = 24", (batch,))
        for index in range(26):
            number = index + 100
            sample_id = db.create_sample(StoredSample(f'child-{index:02}.bin', f'child-fixture-{index}',
                str(Path(directory) / f'absent-child-{index}'), 'application/octet-stream', 2048,
                f'{number:032x}', f'{number:040x}', f'{number:064x}'))
            db.create_scan_job(sample_id, 'Archive acceptance', 'normal', '', batch_id=batch,
                parent_scan_id=26 if index == 25 else 24, scan_role='child',
                relative_path='duplicate%_!.bin' if index in (1, 2) else f'pack/child-{index:02}.bin',
                status='completed', verdict='info', risk_score=0)
        db.refresh_scan_batch_counts(batch)
        # Detached manual children keep management mutations independent of
        # Dashboard/archive pagination fixtures. These files are benign.
        ingest.SAMPLES_DIR.mkdir(exist_ok=True)
        for name in ('management-retry.txt', 'management-delete.txt'):
            path = ingest.SAMPLES_DIR / name
            path.write_text('Benign management acceptance fixture.', encoding='utf-8')
            sample = db.create_sample(StoredSample(name, name, str(path), 'text/plain', path.stat().st_size,
                'd' * 32, 'd' * 40, 'd' * 64))
            scan_id = db.create_scan_job(sample, 'Management acceptance', 'Normal', '',
                                         scan_role='child', status='failed')
            if name == 'management-retry.txt':
                db.create_engine_result(scan_id, EngineResultInput(
                    'Static Metadata', 'failed', False, 'info', 0, None,
                    '<script>benign full-export fixture</script>', 12,
                    error_message='Synthetic management failure',
                ))
        os.environ['MASP_RETENTION_DAYS'] = '30'
        os.environ['MASP_RETENTION_BATCH_SIZE'] = '20'
        path = ingest.SAMPLES_DIR / 'retention-expired.txt'
        path.write_text('Benign retention acceptance fixture.', encoding='utf-8')
        sample = db.create_sample(StoredSample(path.name, path.name, str(path), 'text/plain', path.stat().st_size,
            'e' * 32, 'e' * 40, 'e' * 64))
        expired = db.create_scan_job(sample, '', 'Normal', '', source='api', status='completed')
        with db.connect() as connection:
            connection.execute("UPDATE scan_jobs SET created_at = '2000-01-01 00:00:00' WHERE id = ?", (expired,))
        client = db.create_service_client('console-client', 'Acceptance integration')
        metadata = next(engine for engine in db.list_engine_instances() if engine.adapter_key == 'static_metadata')
        db.create_scan_profile(client, 'Acceptance routing', engine_instance_ids=[metadata.id], is_default=True)
        automation_batch = db.create_scan_batch(source='api', original_filename='automation.zip', archive_mode='lazy_extract_on_detection', service_client_id=client)
        with db.connect() as connection:
            connection.execute("UPDATE scan_batches SET status = 'completed' WHERE id = ?", (automation_batch,))
        for index in range(22):
            number = 200 + index
            sample = db.create_sample(StoredSample(f'ledger-{index:02}.bin', f'ledger-{index}',
                str(Path(directory) / f'ledger-absent-{index}'), 'application/octet-stream', 1024,
                f'{number:032x}', f'{number:040x}', f'{number:064x}'))
            automation_scan = db.create_scan_job(sample, 'Ledger acceptance', 'normal', '', source='api' if index % 2 else 'icap',
                service_client_id=client if index % 2 else None, status='completed', verdict='info', risk_score=0,
                batch_id=automation_batch if index % 2 else None, profile_snapshot_json='{"engines":[]}')
            if index == 19:
                automation_parent = automation_scan
            if index == 21:
                db.create_engine_result(automation_scan, EngineResultInput('Static Metadata', 'completed', False, 'info', 0, None, '<script>inert automation output</script>', 12))
        ancestor = automation_parent
        for index, name in enumerate(('nested-auto.zip', 'inside-auto.txt')):
            number = 300 + index
            sample = db.create_sample(StoredSample(name, f'auto-child-{index}', str(Path(directory) / f'auto-child-{index}'),
                'application/octet-stream', 12, f'{number:032x}', f'{number:040x}', f'{number:064x}'))
            ancestor = db.create_scan_job(sample, 'Automation archive', 'normal', '', source='api',
                service_client_id=client, status='completed', verdict='info', risk_score=0,
                batch_id=automation_batch, parent_scan_id=ancestor, scan_role='child', profile_snapshot_json='{"engines":[]}')
        app = FastAPI()
        app.include_router(router)
        uvicorn.run(app, host="127.0.0.1", port=18765, access_log=False)


if __name__ == "__main__":
    main()
