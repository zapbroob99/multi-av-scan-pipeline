"""Wrap a pilot release and its offline image in one Linux upgrade installer."""

import argparse
import hashlib
import io
import json
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

from package_pilot_release import write_checksum_sidecar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    args = parser.parse_args()
    with zipfile.ZipFile(args.release) as archive:
        metadata_name = next(n for n in archive.namelist() if n.endswith('/RELEASE.json'))
        version = json.loads(archive.read(metadata_name))['version']
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', version):
            raise ValueError('Invalid release version')
        prefix = f'masp-pilot-{version}'
        if args.image.name != f'{prefix}-image.tar':
            raise ValueError('Image filename must match release version')
        output = args.release.parent / f'{prefix}-install.run'
        with tempfile.TemporaryFile() as payload:
            with tarfile.open(fileobj=payload, mode='w:gz') as bundle:
                for name in archive.namelist():
                    path = Path(name)
                    if name.startswith('/') or '..' in path.parts or not name.startswith(prefix + '/'):
                        raise ValueError(f'Invalid archive path: {name}')
                    data = archive.read(name)
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o755 if name.endswith('.sh') else 0o644
                    bundle.addfile(info, io.BytesIO(data))
                bundle.add(args.image, arcname=args.image.name)
                with args.image.open('rb') as source:
                    digest = hashlib.file_digest(source, 'sha256').hexdigest()
                checksum = f'{digest}  {args.image.name}\n'.encode()
                info = tarfile.TarInfo(args.image.name + '.sha256')
                info.size = len(checksum)
                bundle.addfile(info, io.BytesIO(checksum))
            payload.seek(0)
            digest = hashlib.file_digest(payload, 'sha256').hexdigest()
            header = '''#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == --help ]]; then
    echo 'Usage: sudo bash INSTALLER.run [upgrade.sh options]'
    echo 'Use --check to verify this file without installing.'
    echo 'Use --ldap to configure and verify directory login during upgrade (pilot.24+).'
    exit 0
fi
self="$(realpath "$0")"
line=$(awk '/^__MASP_PAYLOAD_BELOW__$/ {print NR + 1; exit}' "$self")
actual=$(tail -n +"$line" "$self" | sha256sum | cut -d ' ' -f1)
[[ "$actual" == @DIGEST@ ]] || { echo 'Installer checksum failed' >&2; exit 1; }
if [[ "${1:-}" == --check ]]; then echo 'Installer checksum OK'; exit 0; fi
[[ $EUID -eq 0 ]] || { echo 'Run with sudo bash' >&2; exit 1; }
root="${MASP_INSTALL_ROOT:-/opt/masp}"
[[ -f "$root/current/.env.pilot" ]] || {
    echo "Existing pilot installation not found at $root/current" >&2; exit 1;
}
mkdir -p "$root"
destination="$root/@PREFIX@"
if [[ -e "$destination" || -L "$destination" ]]; then
  if [[ "${1:-}" != --ldap || ! -d "$destination" || -L "$destination" || "$destination" -ef "$root/current" ]]; then
    echo "Release directory already exists: $destination" >&2
    exit 1
  fi
fi
stage=$(mktemp -d "$root/.installer-XXXXXX")
trap 'echo "Installation interrupted. Offline image retained in $stage" >&2' EXIT
chmod 755 "$stage"
tail -n +"$line" "$self" | tar -xzf - -C "$stage"
if [[ -d "$destination" ]]; then
    # Use the embedded manifest, not the existing directory's own manifest.
    cmp "$stage/@PREFIX@/SHA256SUMS" "$destination/SHA256SUMS"
    (cd "$destination" && sha256sum --quiet -c "$stage/@PREFIX@/SHA256SUMS")
else
    mv "$stage/@PREFIX@" "$destination"
fi
bash "$destination/deploy/pilot/upgrade.sh" --image "$stage/@PREFIX@-image.tar" "$@"
trap - EXIT
rm -rf -- "$stage"
exit 0
__MASP_PAYLOAD_BELOW__
'''.replace('@DIGEST@', digest).replace('@PREFIX@', prefix).encode()
            payload.seek(0)
            with output.open('wb') as target:
                target.write(header)
                shutil.copyfileobj(payload, target)
    with output.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    write_checksum_sidecar(output.with_suffix('.run.sha256'), digest, output.name)
    print(output)


if __name__ == '__main__':
    main()
