#!/usr/bin/env python3
"""
Unit tests for the pure (no network, no scapy) logic in dpi_detector_improved_v2.py.

Run with:
    python test_dpi_detector.py
or:
    python -m unittest test_dpi_detector -v
"""
import unittest

import dpi_detector_improved_v2 as dpi


class CTNameMatchesTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(dpi._ct_name_matches('example.com', {'example.com'}))

    def test_wildcard_covers_subdomain(self):
        self.assertTrue(dpi._ct_name_matches('www.example.com', {'*.example.com'}))

    def test_no_match(self):
        self.assertFalse(dpi._ct_name_matches('www.example.com', {'other.com'}))

    def test_wildcard_does_not_cover_unrelated_domain(self):
        self.assertFalse(dpi._ct_name_matches('www.example.com', {'*.other.com'}))


class IsValidIpTests(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(dpi._is_valid_ip('8.8.8.8'))

    def test_valid_ipv6(self):
        self.assertTrue(dpi._is_valid_ip('2606:4700:4700::1111'))

    def test_rejects_html_or_error_text(self):
        self.assertFalse(dpi._is_valid_ip('<html>rate limited</html>'))

    def test_rejects_empty_string(self):
        self.assertFalse(dpi._is_valid_ip(''))


class RecomputeSuspiciousTests(unittest.TestCase):
    def test_two_high_flags_triggers_suspicious(self):
        out = {'detectors': {
            'a': {'score': 30, 'suspicious': True},
            'b': {'score': 35, 'suspicious': True},
        }}
        dpi._recompute_suspicious(out)
        self.assertTrue(out['suspicious'])
        self.assertEqual(out['dpi_score'], 65)

    def test_single_high_flag_below_total_threshold_not_suspicious(self):
        out = {'detectors': {
            'a': {'score': 30, 'suspicious': True},
            'b': {'score': 5, 'suspicious': False},
        }}
        dpi._recompute_suspicious(out)
        self.assertFalse(out['suspicious'])

    def test_total_score_threshold_triggers_suspicious(self):
        out = {'detectors': {
            'a': {'score': 40, 'suspicious': True},
            'b': {'score': 15, 'suspicious': False},
            'c': {'score': 15, 'suspicious': False},
        }}
        dpi._recompute_suspicious(out)
        self.assertTrue(out['suspicious'])

    def test_low_scores_not_suspicious(self):
        out = {'detectors': {'a': {'score': 5, 'suspicious': False}}}
        dpi._recompute_suspicious(out)
        self.assertFalse(out['suspicious'])
        self.assertEqual(out['dpi_score'], 5)


class FlagRelativeTimingOutliersTests(unittest.TestCase):
    @staticmethod
    def _site(median_ms):
        out = {'detectors': {'tls_timing': {
            'score': 0, 'suspicious': False, 'details': {'median_ms': median_ms},
        }}}
        dpi._recompute_suspicious(out)
        return out

    def test_flags_slow_outlier_relative_to_batch(self):
        sites = {
            'a.com': self._site(100),
            'b.com': self._site(105),
            'c.com': self._site(98),
            'd.com': self._site(2000),
        }
        dpi._flag_relative_timing_outliers(sites)
        self.assertTrue(sites['d.com']['detectors']['tls_timing']['suspicious'])
        self.assertFalse(sites['a.com']['detectors']['tls_timing']['suspicious'])
        self.assertIn('relative_timing_outlier',
                       sites['d.com']['detectors']['tls_timing']['details']['flags'])

    def test_skips_when_fewer_than_three_sites(self):
        sites = {'a.com': self._site(100), 'b.com': self._site(5000)}
        dpi._flag_relative_timing_outliers(sites)
        self.assertFalse(sites['b.com']['detectors']['tls_timing']['suspicious'])

    def test_skips_when_all_values_identical(self):
        sites = {'a.com': self._site(100), 'b.com': self._site(100), 'c.com': self._site(100)}
        dpi._flag_relative_timing_outliers(sites)
        self.assertFalse(any(
            s['detectors']['tls_timing']['suspicious'] for s in sites.values()
        ))

    def test_does_not_flag_a_fast_site(self):
        sites = {
            'a.com': self._site(500),
            'b.com': self._site(510),
            'c.com': self._site(520),
            'd.com': self._site(10),
        }
        dpi._flag_relative_timing_outliers(sites)
        self.assertFalse(sites['d.com']['detectors']['tls_timing']['suspicious'])


class MedianIqrTests(unittest.TestCase):
    def test_empty_list(self):
        self.assertEqual(dpi.median_iqr([]), (None, None))

    def test_basic_values(self):
        med, iqr = dpi.median_iqr([1.0, 2.0, 3.0, 4.0])
        self.assertEqual(med, 2.5)
        self.assertGreaterEqual(iqr, 0)


if __name__ == '__main__':
    unittest.main()
