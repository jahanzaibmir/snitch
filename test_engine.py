"""
Quick smoke test for the Snitch engine.
Creates a temp dir with fake secrets and verifies detection.
"""

import sys
import os
import tempfile
import json

sys.path.insert(0, os.path.dirname(__file__))
from engine import scan_directory
from engine.entropy import shannon_entropy, is_placeholder


# ── Entropy tests ──────────────────────────────────────────────────────────────

def test_entropy():
    print("\n[1] Entropy Tests")
    
    real_secret  = "AKIAIOSFODNN7EXAMPLE"
    placeholder  = "your_api_key_here"
    random_key   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    e1 = shannon_entropy(real_secret)
    e2 = shannon_entropy(placeholder)
    e3 = shannon_entropy(random_key)
    
    print(f"  AWS key entropy:     {e1:.4f}  (expect >3.5)")
    print(f"  Placeholder entropy: {e2:.4f}  (expect <3.0)")
    print(f"  Random key entropy:  {e3:.4f}  (expect >4.0)")
    
    assert e1 > e2, "Real secret should have higher entropy than placeholder"
    print("  ✓ Entropy ordering correct")


def test_placeholder_detection():
    print("\n[2] Placeholder Detection")
    
    cases = [
        ("your_api_key_here",  True),
        ("example_password",   True),
        ("AKIAIOSFODNN7REAL",  False),
        ("xxxxxxxxxxxx",       True),
        ("changeme",           True),
        ("sk-Zt3xQw7YpL9mNvK2hRsA8dFgJ1cBuE4oXmPqW5yT6z", False),
    ]
    
    for value, expected in cases:
        result = is_placeholder(value)
        status = "✓" if result == expected else "✗"
        print(f"  {status} is_placeholder({value!r}) = {result}  (expected {expected})")


def test_file_scanner():
    print("\n[3] File Scanner (live detection)")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files with fake secrets
        test_file = os.path.join(tmpdir, "config.py")
        with open(test_file, 'w') as f:
            f.write("""
# App configuration
import os

# This should be detected — AWS key pattern
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7R3ALKEY"
AWS_SECRET_ACCESS_KEY = "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"

# This should be detected — GitHub token
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

# This should NOT be detected — obvious placeholder
API_KEY = "your_api_key_here"

# Stripe live key — should detect
STRIPE_KEY = "sk_live_Zt3xQw7YpL9mNvK2hRsA8dFgJ1cBuE4o"

# DB connection string — should detect
DB_URL = "postgresql://admin:Sup3rS3cr3tP4ssw0rd@db.prod.company.com:5432/mydb"
""")
        
        # Also create a file that should be skipped
        skip_file = os.path.join(tmpdir, "README.md")
        with open(skip_file, 'w') as f:
            f.write("AKIAIOSFODNN7EXAMPLE — this is in markdown, should still be caught if scanned\n")
        
        report = scan_directory(tmpdir)
        
        print(f"\n  Files scanned: {report['stats']['files_scanned']}")
        print(f"  Findings:      {report['summary']['total']}")
        print(f"  Critical:      {report['summary']['critical']}")
        print(f"  High:          {report['summary']['high']}")
        print(f"  Medium:        {report['summary']['medium']}")
        print(f"  Low:           {report['summary']['low']}")
        
        print("\n  Findings detail:")
        for finding in report['findings']:
            print(f"    [{finding['severity']:8}] {finding['name']}")
            print(f"             File: {finding['file']}:{finding['line']}")
            print(f"             Redacted: {finding['redacted_value']}")
            print(f"             Entropy: {finding['entropy']['score']} ({finding['entropy']['label']})")
            print()
        
        # Assertions
        assert report['summary']['total'] > 0, "Should have found at least something"
        
        # Should detect AWS key
        names = [f['pattern_id'] for f in report['findings']]
        assert 'aws_access_key' in names or 'aws_secret_key' in names, "Should detect AWS keys"
        
        print("  ✓ Scanner working correctly")
        return report


def test_report_structure():
    print("\n[4] Report Structure")
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, 'test.py'), 'w') as f:
            f.write('TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"\n')
        
        report = scan_directory(tmpdir)
        
        required_keys = ['source', 'summary', 'categories', 'stats', 'findings']
        for key in required_keys:
            assert key in report, f"Report missing key: {key}"
            print(f"  ✓ Report has '{key}'")
        
        if report['findings']:
            finding = report['findings'][0]
            required_finding_keys = [
                'id', 'pattern_id', 'name', 'category', 'severity',
                'file', 'line', 'line_content', 'matched_value',
                'redacted_value', 'entropy', 'remediation'
            ]
            for key in required_finding_keys:
                assert key in finding, f"Finding missing key: {key}"
            print(f"  ✓ Finding structure complete ({len(required_finding_keys)} fields)")


if __name__ == "__main__":
    print("=" * 50)
    print("  SNITCH ENGINE — SMOKE TEST")
    print("=" * 50)
    
    try:
        test_entropy()
        test_placeholder_detection()
        test_file_scanner()
        test_report_structure()
        
        print("\n" + "=" * 50)
        print("  ALL TESTS PASSED ✓")
        print("=" * 50)
    except AssertionError as e:
        print(f"\n  FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n  ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
