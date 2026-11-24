"""Exercise the self-extracting installer in an isolated Linux directory."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'installer lifecycle requires an isolated Linux root container')
class PilotInstallerTests(unittest.TestCase):
    def test_extract_delegate_preserve_existing_and_reject_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = 'masp-pilot-0.1.0-test'
            archive_path = root / f'{prefix}.zip'
            with zipfile.ZipFile(archive_path, 'w') as archive:
                archive.writestr(f'{prefix}/RELEASE.json', json.dumps({'version': '0.1.0-test'}))
                archive.writestr(f'{prefix}/deploy/pilot/upgrade.sh',
                                 '#!/bin/bash\nset -e\n[[ "$1" == --image ]]\n'
                                 '[[ -f "$2" && -f "$2.sha256" ]]\n'
                                 'echo delegated > "$MASP_INSTALL_ROOT/done"\n')
            image = root / f'{prefix}-image.tar'
            image.write_bytes(b'test image')
            subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] /
                           'tools/package_pilot_installer.py'), '--release', str(archive_path),
                           '--image', str(image)], check=True, capture_output=True)
            installer = root / f'{prefix}-install.run'
            subprocess.run(['bash', str(installer), '--check'], check=True, capture_output=True)
            installed = root / 'installed'
            (installed / 'current').mkdir(parents=True)
            (installed / 'current/.env.pilot').write_text('existing settings')
            env = dict(os.environ, MASP_INSTALL_ROOT=str(installed))
            subprocess.run(['bash', str(installer)], env=env, check=True, capture_output=True)
            self.assertTrue((installed / 'done').is_file())
            self.assertEqual((installed / 'current/.env.pilot').read_text(), 'existing settings')
            self.assertEqual(list(installed.glob('.installer-*')), [])
            again = subprocess.run(['bash', str(installer)], env=env, capture_output=True)
            self.assertNotEqual(again.returncode, 0)
            with installer.open('ab') as target:
                target.write(b'corruption')
            damaged = subprocess.run(['bash', str(installer), '--check'], capture_output=True)
            self.assertNotEqual(damaged.returncode, 0)


if __name__ == '__main__':
    unittest.main()
