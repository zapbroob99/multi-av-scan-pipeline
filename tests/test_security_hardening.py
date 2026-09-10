import asyncio
from email.message import Message
import hashlib
from http.client import IncompleteRead
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch
from urllib.request import HTTPSHandler, build_opener
from urllib.response import addinfourl

from fastapi import FastAPI, File, HTTPException, UploadFile
from starlette.formparsers import SpooledTemporaryFile

from app.models import EngineResultInput
from app.services.upload_admission import UploadAdmissionRoute, upload_body_limit
from app.workers import control_api_worker as worker


class RedirectTests(unittest.TestCase):
    def test_interrupted_response_becomes_recoverable_worker_error(self):
        client = worker.WorkerControlClient('https://masp.invalid/api/', 'synthetic-token')
        for error in (TimeoutError('read timeout'), IncompleteRead(b'partial')):
            with self.subTest(error=type(error).__name__):
                response = MagicMock()
                response.__enter__.return_value = response
                response.status = 200
                response.headers = {}
                response.read.side_effect = error
                with patch.object(client, '_request', return_value=response):
                    with self.assertRaises(worker.WorkerControlError):
                        client.post_json('claim', {})
                    with self.assertRaises(worker.WorkerControlError):
                        client.download_sample('sample', {}, expected_sha256='0'*64,
                                               expected_size=10, filename='sample.bin')

    def test_authenticated_requests_never_follow_any_redirect(self):
        for code in (301, 302, 303, 307, 308):
            for destination in ('https://other.invalid/token', 'http://other.invalid/token',
                                'https://masp.invalid/elsewhere'):
                with self.subTest(code=code, destination=destination):
                    sent = []

                    class FakeHTTPS(HTTPSHandler):
                        def https_open(self, request):
                            sent.append(request.full_url)
                            headers = Message()
                            headers['Location'] = destination
                            response = addinfourl(io.BytesIO(), headers, request.full_url, code)
                            response.msg = 'Redirect'
                            return response

                    def opener(*handlers):
                        return build_opener(*[h for h in handlers if not isinstance(h, HTTPSHandler)], FakeHTTPS())

                    client = worker.WorkerControlClient('https://masp.invalid/api/', 'synthetic-token')
                    with patch('app.services.http_transport.build_opener', side_effect=opener):
                        with self.assertRaises(worker.WorkerControlError):
                            client.post_json('claim', {})
                    self.assertEqual(sent, ['https://masp.invalid/api/claim'])


class UploadAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.app = FastAPI()
        self.app.router.route_class = UploadAdmissionRoute
        self.handled = 0

        @self.app.post('/api/v1/scans')
        async def upload(sample: UploadFile = File(...)):
            self.handled += 1
            return {'bytes': len(await sample.read())}

    def invoke(self, chunks, *, authorized=True, content_length=None, limit=256):
        self.reads = 0
        messages = []
        files = []
        scope = dict(type='http', asgi={'version': '3.0'}, http_version='1.1',
                     method='POST', scheme='http', path='/api/v1/scans',
                     raw_path=b'/api/v1/scans', query_string=b'', root_path='',
                     headers=[(b'content-type', b'multipart/form-data; boundary=review')],
                     client=('127.0.0.1', 1234), server=('localhost', 80))
        if content_length is not None:
            scope['headers'].append((b'content-length', str(content_length).encode()))

        def authenticate(_request):
            if not authorized:
                raise HTTPException(401, 'Bearer token required.')

        def spool(*args, **kwargs):
            file = SpooledTemporaryFile(*args, **kwargs)
            files.append(file)
            return file

        async def receive():
            index = self.reads
            self.reads += 1
            self.assertLess(index, len(chunks), 'request read beyond the supplied body')
            return {'type': 'http.request', 'body': chunks[index], 'more_body': index < len(chunks)-1}

        async def send(message):
            messages.append(message)

        with patch('app.services.upload_admission.require_api_token', side_effect=authenticate), \
             patch('app.services.upload_admission.upload_body_limit', return_value=limit), \
             patch('starlette.formparsers.SpooledTemporaryFile', side_effect=spool):
            asyncio.run(self.app(scope, receive, send))
        return next(m['status'] for m in messages if m['type'] == 'http.response.start'), files

    def test_invalid_token_is_rejected_without_reading_the_body(self):
        status, _ = self.invoke([b'x' * 512], authorized=False)
        self.assertEqual((status, self.reads, self.handled), (401, 0, 0))

    def test_declared_oversize_is_rejected_before_body_read(self):
        status, _ = self.invoke([b'x'], content_length=257)
        self.assertEqual((status, self.reads, self.handled), (413, 0, 0))

    def test_chunked_or_underdeclared_body_is_bounded_and_spools_are_closed(self):
        start = b'--review\r\nContent-Disposition: form-data; name="sample"; filename="a.bin"\r\n\r\nabc'
        for declared in (None, 1):
            with self.subTest(content_length=declared):
                status, files = self.invoke([start, b'x' * 512, b'\r\n--review--\r\n'], content_length=declared)
                self.assertEqual((status, self.reads, self.handled), (413, 2, 0))
                self.assertTrue(files)
                self.assertTrue(all(f.closed for f in files))

    def test_extra_file_parts_count_toward_total_body_limit(self):
        start = b'--review\r\nContent-Disposition: form-data; name="sample"; filename="a"\r\n\r\nx\r\n'
        extra = b'--review\r\nContent-Disposition: form-data; name="unused"; filename="b"\r\n\r\n'
        status, files = self.invoke([start + extra, b'x' * 512])
        self.assertEqual((status, self.handled), (413, 0))
        self.assertTrue(all(f.closed for f in files))

    def test_valid_upload_still_reaches_the_handler(self):
        body = b'--review\r\nContent-Disposition: form-data; name="sample"; filename="a"\r\n\r\nabc\r\n--review--\r\n'
        status, _ = self.invoke([body])
        self.assertEqual((status, self.handled), (200, 1))

    def test_deployment_ceiling_cannot_be_removed_by_policy(self):
        with patch.dict('os.environ', {'MASP_HTTP_UPLOAD_MAX_BYTES': '512'}), \
             patch('app.services.upload_admission.configured_upload_max_bytes', return_value=None):
            self.assertEqual(upload_body_limit(), 512)


class WorkerLivenessTests(unittest.TestCase):
    def test_lost_lease_during_download_never_scans_or_submits(self):
        attempted = threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.bin'
            path.write_bytes(b'abc')

            class Client:
                def post_json(self, route, payload):
                    if route.endswith('/lease'):
                        attempted.set()
                        raise worker.WorkerControlError('ownership lost')

                def download_sample(self, *args, **kwargs):
                    if not attempted.wait(2):
                        raise AssertionError('renewal did not run during download')
                    for thread in threading.enumerate():
                        if thread.name == 'control-lease-1':
                            thread.join(timeout=2)
                            if thread.is_alive():
                                raise AssertionError('failed renewal did not stop')
                    return path

            claim = {'job': {'id': 1, 'scan_id': 2, 'attempt_generation': 1, 'lease_seconds': 30},
                     'sample': {'download_path': '/sample', 'sha256': '0'*64,
                                'size_bytes': 3, 'original_filename': 'sample.bin'}}
            client = Client()
            with patch.object(worker, 'job_lease_renewal_seconds', return_value=.005), \
                 patch.object(worker, 'run_engine') as scan, \
                 patch.object(client, 'post_json', wraps=client.post_json) as post:
                with self.assertRaises(worker.WorkerControlError):
                    worker.run_claim(client, claim, 11)
            scan.assert_not_called()
            self.assertFalse(any(call.args[0].endswith('/result') for call in post.call_args_list))
            self.assertFalse(path.exists())

    def test_download_scan_and_submission_keep_heartbeat_and_lease_alive(self):
        heartbeat = threading.Event()
        lease = threading.Event()
        calls = []
        content = b'safe review sample'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.bin'
            path.write_bytes(content)
            testcase = self

            class Client:
                def post_json(self, route, payload):
                    calls.append(route)
                    if route == 'heartbeat':
                        heartbeat.set()
                    if route.endswith('/lease'):
                        lease.set()
                    if route.endswith('/result'):
                        heartbeat.clear()
                        lease.clear()
                        testcase.assertTrue(heartbeat.wait(2), 'heartbeat stopped before result ack')
                        testcase.assertTrue(lease.wait(2), 'lease stopped before result ack')
                    return {}

                def download_sample(self, *args, **kwargs):
                    heartbeat.clear()
                    testcase.assertTrue(heartbeat.wait(2), 'no heartbeat during download')
                    testcase.assertTrue(lease.wait(2), 'lease started after download')
                    return path

            def scan(*args):
                heartbeat.clear()
                lease.clear()
                self.assertTrue(heartbeat.wait(2), 'no heartbeat during scan')
                self.assertTrue(lease.wait(2), 'no lease during scan')
                return EngineResultInput(engine_name='Metadata', status='completed', detected=False,
                    severity='info', confidence=100, signature=None, raw_output='', duration_ms=1)

            claim = {
                'job': {'id': 1, 'scan_id': 2, 'attempt_generation': 3, 'lease_seconds': 30},
                'engine': {'id': 1, 'adapter_key': 'static_metadata', 'display_name': 'Metadata', 'config': {}},
                'sample': {'download_path': '/sample', 'original_filename': 'sample.bin',
                    'size_bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(),
                    'md5': '0'*32, 'sha1': '0'*40},
                'scan': {'source': 'api'},
            }
            with patch.object(worker, 'heartbeat_interval_seconds', return_value=.005), \
                 patch.object(worker, 'job_lease_renewal_seconds', return_value=.005), \
                 patch.object(worker, 'run_engine', side_effect=scan):
                worker.run_claim(Client(), claim, 11)
            self.assertFalse(path.exists())
            self.assertIn('jobs/1/result', calls)

    def test_health_probe_keeps_sending_heartbeat(self):
        beat = threading.Event()

        class Client:
            def post_json(self, route, payload):
                if route == 'heartbeat':
                    beat.set()

        def probe(*args):
            beat.clear()
            self.assertTrue(beat.wait(2))
            return {'ok': True, 'status': 'healthy'}

        claim = {'engine': {'id': 1, 'adapter_key': 'static_metadata', 'display_name': 'M', 'config': {}},
                 'check_generation': 1}
        with patch.object(worker, 'heartbeat_interval_seconds', return_value=.005), \
             patch.object(worker, 'engine_health', side_effect=probe):
            worker.run_health_claim(Client(), claim, 11)
