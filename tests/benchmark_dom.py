"""Benchmark: DOM XSS detection rate across 3 vulnerable-app ranges.

Usage: python3 tests/benchmark_dom.py
Prints a per-range comparison table and exits non-zero if any range
falls below 100% recall or precision.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.domScanner import scan_dom

BENCHMARKS_DIR = os.path.dirname(os.path.abspath(__file__)) + '/benchmarks'
RANGES = ('dvwa', 'webgoat', 'xssgame')


def evaluate_range(range_dir):
    """Runs scan_dom over every labelled page of a range.

    Returns (stats, rows) where stats has tp/fp/fn/tn/recall/precision.
    """
    with open(os.path.join(range_dir, 'labels.json')) as f:
        labels = json.load(f)
    tp = fp = fn = tn = 0
    rows = []
    for page, label in sorted(labels.items()):
        with open(os.path.join(range_dir, page)) as f:
            response = f.read()
        findings = scan_dom(response)
        detected = any(f['type'] in ('dom-xss', 'postmessage-xss') for f in findings)
        expected = label['vulnerable']
        if expected and detected:
            tp += 1
        elif expected and not detected:
            fn += 1
        elif not expected and detected:
            fp += 1
        else:
            tn += 1
        rows.append({
            'page': page,
            'expected': expected,
            'detected': detected,
            'findings': [f['type'] for f in findings],
        })
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    stats = {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
             'recall': recall, 'precision': precision}
    return stats, rows


def main():
    print('DOM XSS detection benchmark (XSStrike core/domScanner.py)\n')
    header = '%-10s %6s %5s %9s %9s %8s %10s' % (
        'range', 'pages', 'vuln', 'detected', 'missed', 'recall', 'precision')
    print(header)
    print('-' * len(header))
    ok = True
    for name in RANGES:
        stats, rows = evaluate_range(os.path.join(BENCHMARKS_DIR, name))
        pages = len(rows)
        vuln = sum(1 for r in rows if r['expected'])
        detected = sum(1 for r in rows if r['expected'] and r['detected'])
        missed = vuln - detected
        print('%-10s %6d %5d %9d %9d %7.1f%% %9.1f%%' % (
            name, pages, vuln, detected, missed,
            stats['recall'] * 100, stats['precision'] * 100))
        for row in rows:
            mark = 'OK' if row['expected'] == row['detected'] else 'FAIL'
            print('  [%s] %-28s expected=%-5s detected=%-5s %s' % (
                mark, row['page'], row['expected'], row['detected'],
                ','.join(row['findings']) or '-'))
        if stats['recall'] < 1.0 or stats['precision'] < 1.0:
            ok = False
    print()
    if ok:
        print('PASS: 100% recall and precision on all 3 ranges')
        return 0
    print('FAIL: detection below 100% on at least one range')
    return 1


if __name__ == '__main__':
    sys.exit(main())
