import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.dom import dom
from core.domScanner import classify_origin_check, scan_dom


class TestDomXssDetection(unittest.TestCase):
    def test_location_hash_to_innerhtml(self):
        html = '<script>document.getElementById("x").innerHTML = location.hash;</script>'
        findings = scan_dom(html)
        self.assertTrue(any(f['type'] == 'dom-xss' for f in findings))

    def test_taint_propagation_through_variables(self):
        html = ('<script>'
                'var q = location.search.substring(1);'
                'var decoded = decodeURIComponent(q);'
                'document.write(decoded);'
                '</script>')
        findings = scan_dom(html)
        dom_findings = [f for f in findings if f['type'] == 'dom-xss']
        self.assertTrue(dom_findings)
        self.assertEqual(dom_findings[0]['sink'], 'document.write')

    def test_eval_sink(self):
        html = '<script>eval("var x = " + window.name);</script>'
        self.assertTrue(any(f['type'] == 'dom-xss' for f in scan_dom(html)))

    def test_safe_page_has_no_findings(self):
        html = ('<script>'
                'var hash = location.hash;'
                'document.getElementById("x").textContent = hash;'
                '</script>')
        self.assertEqual(scan_dom(html), [])

    def test_no_script_no_findings(self):
        self.assertEqual(scan_dom('<html><body>hello</body></html>'), [])


class TestPostMessage(unittest.TestCase):
    def test_no_origin_check_with_sink_is_high(self):
        html = ('<script>'
                'window.addEventListener("message", function (e) {'
                '  document.getElementById("m").innerHTML = e.data;'
                '});'
                '</script>')
        findings = scan_dom(html)
        pm = [f for f in findings if f['type'] == 'postmessage-xss']
        self.assertTrue(pm)
        self.assertEqual(pm[0]['origin_check'], 'none')
        self.assertEqual(pm[0]['severity'], 'high')

    def test_strict_origin_check_no_sink_is_safe(self):
        html = ('<script>'
                'window.addEventListener("message", function (e) {'
                '  if (e.origin !== "https://trusted.example.com") { return; }'
                '  document.getElementById("m").textContent = e.data;'
                '});'
                '</script>')
        self.assertEqual(scan_dom(html), [])

    def test_weak_origin_check_still_flagged(self):
        html = ('<script>'
                'window.onmessage = function (evt) {'
                '  if (evt.origin.indexOf("example.com") === -1) { return; }'
                '  document.write(evt.data);'
                '};'
                '</script>')
        findings = scan_dom(html)
        pm = [f for f in findings if f['type'] == 'postmessage-xss']
        self.assertTrue(pm)
        self.assertEqual(pm[0]['origin_check'], 'weak')

    def test_data_used_without_origin_check_and_without_sink(self):
        html = ('<script>'
                'window.addEventListener("message", function (e) {'
                '  var payload = e.data;'
                '  console.log(payload);'
                '});'
                '</script>')
        findings = scan_dom(html)
        self.assertTrue(any(f['type'] == 'postmessage-no-origin-check' for f in findings))

    def test_classify_origin_check(self):
        self.assertEqual(classify_origin_check('if (e.origin !== "https://a.com") return;', 'e'), 'strict')
        self.assertEqual(classify_origin_check('if (e.origin.indexOf("a.com") === -1) return;', 'e'), 'weak')
        self.assertEqual(classify_origin_check('document.write(e.data);', 'e'), 'none')
        self.assertEqual(classify_origin_check('if (["https://a.com"].includes(e.origin)) {}', 'e'), 'strict')


class TestBackwardCompatibility(unittest.TestCase):
    """The legacy dom() highlighter must keep working alongside scan_dom."""

    def test_dom_highlighter_still_flags_sources_and_sinks(self):
        html = '<script>document.write(location.hash);</script>'
        self.assertTrue(dom(html))

    def test_dom_highlighter_silent_on_safe_page(self):
        html = '<script>var a = 1; console.log(a);</script>'
        self.assertEqual(dom(html), [])


if __name__ == '__main__':
    unittest.main()
