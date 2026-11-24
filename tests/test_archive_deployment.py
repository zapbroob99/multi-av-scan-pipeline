"""Render the shipped Compose templates without starting any container."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('docker'), 'Docker Compose CLI is required')
class ArchiveDeploymentTests(unittest.TestCase):
    def test_custom_archive_bounds_reach_each_intake_execution_service(self):
        values = dict(MASP_ARCHIVE_MAX_FILES='123', MASP_ARCHIVE_MAX_TOTAL_BYTES='9876543',
            MASP_ARCHIVE_MAX_SINGLE_FILE_BYTES='1234567', MASP_ARCHIVE_MAX_DEPTH='6', MASP_ARCHIVE_MAX_NESTED_LEVELS='2')
        for variant, env_file in [('pilot', '.env.pilot.example'), ('prod', '.env.production.example')]:
            with self.subTest(variant=variant):
                result = subprocess.run(['docker', 'compose', '--env-file', env_file, '-f', f'docker-compose.{variant}.yml',
                    '--profile', '*', 'config', '--format', 'json'], cwd=ROOT,
                    env={**os.environ, **values}, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, 'Compose template did not render')
                services = json.loads(result.stdout)['services']
                for name in ('app', 'worker', 'icap', 'deferred-intake'):
                    self.assertIn(name, services)
                    for key, value in values.items():
                        self.assertEqual(services[name]['environment'].get(key), value, f'{variant}/{name}/{key}')
