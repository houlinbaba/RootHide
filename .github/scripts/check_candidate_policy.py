#!/usr/bin/env python3
"""Enforce research-only packaging while known cross-component failures remain."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--research', action='store_true')
    mode.add_argument('--require-distributable', action='store_true')
    args = parser.parse_args()
    status = json.loads((ROOT / 'docs/review/candidate-status.json').read_text())
    if args.research:
        print('COMPILE/RESEARCH ONLY. F3=' + status['F3'] + '; F1=' + status['F1'] +
              '. Output is not a device diagnostic or repair candidate.')
        return 0
    permitted = (status['distributable'] is True and status['classification'] == 'repair-candidate'
                 and status['F3'] == 'PASS' and status['F1'] == 'PASS')
    if not permitted:
        print('PACKAGING BLOCKED: known cross-component failures. Explicit RESEARCH_BUILD=1 is required for compile/research output; distribution is not authorized.')
    return 0 if permitted else 1

if __name__ == '__main__':
    raise SystemExit(main())
