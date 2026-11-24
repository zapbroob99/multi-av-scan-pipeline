import io
import os
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from pydantic import ValidationError
from fastapi import HTTPException

from app.services import aselix
from app import database as db


class AselixTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temporary.cleanup)
        self.enterContext(patch.object(db, "DB_PATH", Path(temporary.name) / "test.db"))
        self.enterContext(patch.object(db, "DATABASE_URL", ""))
        db.init_db()
        self.enterContext(patch.dict(os.environ, MASP_ASELIX_ENABLED='1',
            MASP_ASELIX_URL='https://ai.test/v1/chat/completions', MASP_ASELIX_MODEL='model',
            MASP_ASELIX_API_KEY='test-only', MASP_ASELIX_CA_PEM_B64=''))
        self.question = aselix.ChatQuestion(question='help')
        self.send = self.enterContext(patch.object(aselix.http_transport, 'open_without_redirects'))

    def test_configuration_and_message_bounds(self):
        for url in ('http://example.com/v1/chat/completions', 'https://user:pass@example.com/v1/chat/completions',
                    'https://example.com/v1/chat/completions?token=query', ''):
            with patch.dict(os.environ, MASP_ASELIX_URL=url), self.assertRaises(HTTPException) as failed:
                aselix.ask(self.question)
            self.assertEqual(failed.exception.status_code, 503)
        self.send.assert_not_called()
        for kwargs in ({'question': '  '}, {'question': 'x' * 1501}, {'question': 'q', 'history': [
                {'question': 'q', 'answer': 'a'}] * 4}):
            with self.assertRaises(ValidationError):
                aselix.ChatQuestion(**kwargs)

    def test_invalid_upstream_and_bounded_concurrency(self):
        for reply in (b'x' * 65537, b'{"choices":[]}', b'not json'):
            self.send.return_value = io.BytesIO(reply)
            with self.assertRaises(HTTPException) as failed:
                aselix.ask(self.question)
            self.assertEqual(failed.exception.status_code, 502)
        with aselix._slots, aselix._slots, aselix._slots, aselix._slots:
            with self.assertRaises(HTTPException) as failed:
                aselix.ask(self.question)
            self.assertEqual(failed.exception.status_code, 429)
