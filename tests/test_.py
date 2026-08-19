```python
import unittest
from core.scorer import score, Confidence

class TestScoringEngine(unittest.TestCase):
    def test_high_confidence_exact_match(self):
        """Test that a 404 with a valid signature triggers High Risk."""
        result = score(
            is_cname_candidate=True,
            provider_matched=True,
            http_reachable=True,
            http_status_code=404,
            signature_found=True,
            subdomain="test.example.com"
        )
        self.assertEqual(result.confidence, Confidence.HIGH)

    def test_medium_confidence_odd_status(self):
        """Test that a matching signature on a non-404 status triggers Medium Risk."""
        result = score(
            is_cname_candidate=True,
            provider_matched=True,
            http_reachable=True,
            http_status_code=403,
            signature_found=True,
            subdomain="test.example.com"
        )
        self.assertEqual(result.confidence, Confidence.MEDIUM)

    def test_not_a_candidate(self):
        """Test that non-CNAMEs are immediately scored as None."""
        result = score(
            is_cname_candidate=False,
            provider_matched=False,
            http_reachable=None,
            http_status_code=None,
            signature_found=None,
            subdomain="live.example.com"
        )
        self.assertEqual(result.confidence, Confidence.NONE)

if __name__ == '__main__':
    unittest.main()