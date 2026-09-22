import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import export_browser_openapi as exporter


class BrowserContractTests(unittest.TestCase):
    def test_snapshot_is_deterministic_and_current(self):
        first = exporter.render()
        self.assertEqual(first, exporter.render())
        self.assertEqual(first, exporter.OUTPUT.read_text(encoding='utf-8'))

    # File downloads are the only browser reads outside the typed JSON contract:
    # JSON escaping of recorded engine output can multiply its size. Enumerate
    # them so a new non-JSON route cannot appear unnoticed.
    PLAIN_TEXT_DOWNLOADS = {
        ('/api/ui/v1/scans/{scan_id}/results/{result_id}/output', 'get'),
        ('/api/ui/v1/api-ledger/scans/{scan_id}/results/{result_id}/output', 'get'),
    }

    def test_every_browser_success_and_error_has_a_contract(self):
        schema = exporter.schema()
        operations = []
        seen_downloads = set()
        for path, methods in schema['paths'].items():
            self.assertTrue(path.startswith('/api/ui/v1/'))
            for method, operation in methods.items():
                if method not in ('get', 'post', 'put', 'delete'):
                    continue
                operations.append(operation['operationId'])
                download = (path, method) in self.PLAIN_TEXT_DOWNLOADS
                success = {code: response for code, response in operation['responses'].items() if code.startswith('2')}
                self.assertTrue(success, (path, method))
                for code, response in success.items():
                    if code == '204':
                        self.assertNotIn('content', response)
                    elif download:
                        seen_downloads.add((path, method))
                        # Exactly one media type: never claim the download is JSON.
                        self.assertEqual(response['content'], {'text/plain': {'schema': {'type': 'string'}}}, (path, method))
                    else:
                        self.assertIn('$ref', response['content']['application/json']['schema'], (path, method))
                # Errors stay JSON everywhere, including on the downloads: an
                # HTTPException returns JSON whatever the success media type is.
                self.assertEqual(operation['responses']['422']['content']['application/json']['schema'],
                                 {'$ref': '#/components/schemas/ErrorPayload'})
        self.assertEqual(len(operations), len(set(operations)))
        self.assertEqual(seen_downloads, self.PLAIN_TEXT_DOWNLOADS)

    def test_schema_preserves_async_health_multipart_and_nullable_fields(self):
        schema = exporter.schema()
        paths, models = schema['paths'], schema['components']['schemas']
        health = paths['/api/ui/v1/engines/{instance_id}/checks']['post']['responses']
        self.assertEqual(health['200']['content'], health['202']['content'])
        submission = paths['/api/ui/v1/scans']['post']
        self.assertIn('202', submission['responses'])
        self.assertEqual(set(submission['requestBody']['content']), {'multipart/form-data'})
        ref = submission['requestBody']['content']['multipart/form-data']['schema']['$ref'].split('/')[-1]
        self.assertEqual(models[ref]['properties']['sample']['contentMediaType'], 'application/octet-stream')
        self.assertIn('sample', models[ref]['required'])
        self.assertIn({'type': 'null'}, models['ScanReport']['properties']['decision']['anyOf'])
        self.assertEqual(models['ConfigBody']['additionalProperties'], False)
        self.assertIn('$ref', models['AdapterPayload']['properties']['capabilities'])
        self.assertEqual(models['EnginePayload']['properties']['config']['additionalProperties'], {'type': 'string'})
        self.assertIn('required', models['FieldPayload']['required'])
        self.assertEqual(models['ErrorPayload']['properties']['detail']['type'], 'string')

    def test_check_detects_drift_or_missing_file_without_rewriting(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'schema.json'
            with patch.object(exporter, 'OUTPUT', output), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(exporter.main(['--check']), 1)
                self.assertFalse(output.exists())
                self.assertEqual(exporter.main([]), 0)
                before = output.read_bytes()
                self.assertEqual(exporter.main(['--check']), 0)
                changed = json.loads(exporter.render())
                changed['info']['version'] = 'changed'
                with patch.object(exporter, 'schema', return_value=changed):
                    self.assertEqual(exporter.main(['--check']), 1)
                self.assertEqual(output.read_bytes(), before)

    def test_export_does_not_initialize_runtime_or_access_database_network_or_samples(self):
        code = '''
import os, sys
from pathlib import Path
root = Path.cwd()
def audit(event, args):
    if event in ('sqlite3.connect', 'socket.connect', 'subprocess.Popen'):
        raise AssertionError('Runtime I/O during schema export: ' + event)
    if event == 'import' and args[0] == 'app.main':
        raise AssertionError('Production app imported during schema export')
    if event == 'open' and isinstance(args[0], (str, bytes)):
        path = Path(os.fsdecode(args[0])).resolve()
        if path.is_relative_to(root / 'data') or path.name.startswith('.env'):
            raise AssertionError('Deployment data accessed during schema export')
sys.addaudithook(audit)
from tools.export_browser_openapi import main
assert 'app.main' not in sys.modules
raise SystemExit(main(['--check']))
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=exporter.ROOT,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'MASP_DATABASE_URL': 'postgresql://invalid.invalid/never'},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
