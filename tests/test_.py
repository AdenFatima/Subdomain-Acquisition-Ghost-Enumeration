import unittest
from unittest.mock import patch
from core.scorer import score, Confidence
from core.dns_engine import DNSEngine
from providers import ProviderRegistry

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


class TestProviderRegistry(unittest.TestCase):
    def setUp(self):
        # Initialize the registry to test the regex matching logic
        self.registry = ProviderRegistry()

    def test_github_classification(self):
        """Test that GitHub Pages patterns are caught accurately."""
        match = self.registry.classify("adenfatima.github.io")
        self.assertIsNotNone(match)
        self.assertEqual(match.provider_id, "github_pages")

    def test_unknown_provider(self):
        """Test that unmapped infrastructure is cleanly skipped."""
        match = self.registry.classify("unknown-server.com")
        self.assertIsNone(match)


class TestDNSEngine(unittest.IsolatedAsyncioTestCase):
    @patch('core.dns_engine.DNSEngine._resolve_cname')
    @patch('core.dns_engine.DNSEngine._resolve_a_or_aaaa')
    async def test_follow_chain_no_cname(self, mock_a, mock_cname):
        """Test standard A record resolution with no dangling CNAME."""
        mock_cname.return_value = None
        mock_a.return_value = True

        engine = DNSEngine()
        result = await engine._follow_chain("live.example.com")

        self.assertFalse(result.is_cname_candidate)
        self.assertTrue(result.has_a_record)
        self.assertEqual(result.cname_chain, [])

    @patch('core.dns_engine.DNSEngine._resolve_cname')
    @patch('core.dns_engine.DNSEngine._resolve_a_or_aaaa')
    async def test_follow_chain_with_dangling_cname(self, mock_a, mock_cname):
        """Test a vulnerable CNAME chain that points to an abandoned edge server."""
        # Simulates: test.example.com -> target.github.io -> (No further CNAME)
        mock_cname.side_effect = ["target.github.io", None]
        mock_a.return_value = False  # The final target lacks an A record

        engine = DNSEngine()
        result = await engine._follow_chain("test.example.com")

        self.assertTrue(result.is_cname_candidate)
        self.assertFalse(result.has_a_record)
        self.assertEqual(result.final_target, "target.github.io")
        self.assertEqual(result.cname_chain, ["target.github.io"])
        
    @patch('core.dns_engine.DNSEngine._resolve_cname')
    @patch('core.dns_engine.DNSEngine._resolve_a_or_aaaa')
    async def test_follow_chain_max_depth_loop(self, mock_a, mock_cname):
        """Test that the engine breaks out of infinite CNAME loops safely."""
        # Simulates a misconfigured DNS setup looping on itself
        mock_cname.return_value = "loop.example.com"
        mock_a.return_value = False
        
        engine = DNSEngine()
        result = await engine._follow_chain("loop.example.com")
        
        # Should stop safely at the MAX_CNAME_CHAIN_DEPTH (which is 8)
        self.assertEqual(len(result.cname_chain), 8)

if __name__ == '__main__':
    unittest.main()