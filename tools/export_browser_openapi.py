"""Export browser contracts without importing app.main, starting servers or opening a DB."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUTPUT = ROOT / 'frontend' / 'contracts' / 'browser.openapi.json'


def schema():
    from fastapi import FastAPI
    from app.services.ui_api import router

    app = FastAPI(title='MASP Browser API', version='1')
    app.include_router(router)
    return app.openapi()


def render():
    return json.dumps(schema(), ensure_ascii=True, sort_keys=True, indent=2) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Read-only drift check; never rewrite the snapshot.')
    args = parser.parse_args(argv)
    expected = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding='utf-8') != expected:
            print('Browser OpenAPI snapshot is stale. Run npm --prefix frontend run contracts:generate.', file=sys.stderr)
            return 1
        print('Browser OpenAPI snapshot matches backend routes.')
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(expected, encoding='utf-8', newline='\n')
        print('Exported frontend/contracts/browser.openapi.json')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
