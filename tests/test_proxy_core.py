from __future__ import annotations

import base64
import binascii
import hashlib
import unittest

from app.core.auth import LEGACY_PBKDF2_ITERS, hash_password, password_needs_rehash, verify_password
from app.proxy.catalog import ProxyFeedback, filter_proxies as catalog_filter, russian_reachability_score
from app.proxy.decoder import decode_secret
from app.proxy.harvester import parse_raw_text
from app.proxy.sources import DEFAULT_SOURCE_URLS
from app.proxy.pipeline import calculate_transport_score
from app.proxy.selector import select_first_reachable
from app.proxy.personalization import normalize_client_profile, personalize_proxies


CORE = "00112233445566778899aabbccddeeff"
FAKE_TLS = "ee" + (bytes.fromhex(CORE) + b"example.ru").hex()


class ParserTests(unittest.TestCase):
    def test_default_sources_are_https_and_unique(self) -> None:
        self.assertTrue(all(url.startswith("https://") for url in DEFAULT_SOURCE_URLS))
        self.assertEqual(len(DEFAULT_SOURCE_URLS), len(set(DEFAULT_SOURCE_URLS)))

    def test_parses_encoded_query_and_normalizes_host(self) -> None:
        text = (
            "https://t.me/proxy?server=EXAMPLE.COM&amp;port=443&amp;secret=" + FAKE_TLS
        )
        proxies = parse_raw_text(text, "fixture")
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0].host, "example.com")
        self.assertEqual(proxies[0].port, 443)

    def test_rejects_private_and_invalid_addresses(self) -> None:
        text = f"tg://proxy?server=127.0.0.1&port=443&secret={CORE}"
        self.assertEqual(parse_raw_text(text), [])

    def test_parses_base64_only_payload(self) -> None:
        link = f"tg://proxy?server=example.com&port=443&secret={CORE}"
        payload = base64.b64encode(link.encode()).decode()
        proxies = parse_raw_text(payload)
        self.assertEqual(len(proxies), 1)

    def test_parses_urlsafe_base64_without_padding(self) -> None:
        link = f"tg://proxy?server=example.com&port=443&secret={CORE}"
        payload = base64.urlsafe_b64encode(link.encode()).decode().rstrip("=")
        self.assertEqual(len(parse_raw_text(payload)), 1)

    def test_parses_structured_json(self) -> None:
        text = '{"items":[{"server":"example.com","port":443,"secret":"' + CORE + '"}]}'
        proxies = parse_raw_text(text)
        self.assertEqual([(p.host, p.port) for p in proxies], [("example.com", 443)])


class DecoderAndScoreTests(unittest.TestCase):
    def test_randpad_requires_exact_secret_length(self) -> None:
        self.assertTrue(decode_secret("dd" + CORE).is_valid)
        self.assertFalse(decode_secret("dd" + CORE + "00").is_valid)

    def test_verified_tls_cover_improves_observed_score(self) -> None:
        decoded = decode_secret(FAKE_TLS)
        basic = calculate_transport_score(decoded, 443, "tls_rejected")
        verified = calculate_transport_score(decoded, 443, "tls_verified")
        self.assertGreater(verified, basic)
        self.assertLessEqual(verified, 100)


class CatalogTests(unittest.TestCase):
    def test_feedback_is_personal_until_quorum(self) -> None:
        reports = ProxyFeedback(quorum=3)
        self.assertFalse(reports.report_failure("p1", 1, now=1000))
        self.assertTrue(reports.is_blocked("p1", 1, now=1001))
        self.assertFalse(reports.is_blocked("p1", 2, now=1001))
        reports.report_failure("p1", 2, now=1002)
        self.assertTrue(reports.report_failure("p1", 3, now=1003))
        self.assertTrue(reports.is_blocked("p1", 99, now=1004))

    def test_quality_sort_uses_transport_score(self) -> None:
        rows = [
            {"id": "a", "secret": CORE, "transport_score": 20, "ping_ms": 10},
            {"id": "b", "secret": FAKE_TLS, "transport_score": 90, "ping_ms": 50},
        ]
        result = catalog_filter(rows, sort_by="quality", limit=10)
        self.assertEqual([row["id"] for row in result], ["b", "a"])

    def test_success_vote_clears_personal_failure_and_affects_quorum(self) -> None:
        reports = ProxyFeedback(quorum=2)
        reports.report_failure("p1", 1, now=1000)
        reports.report_failure("p1", 2, now=1001)
        self.assertTrue(reports.is_blocked("p1", 99, now=1002))
        reports.report_success("p1", 1, now=1003)
        self.assertFalse(reports.is_blocked("p1", 1, now=1004))
        self.assertFalse(reports.is_blocked("p1", 99, now=1004))

    def test_recommended_sort_prefers_russian_feedback(self) -> None:
        rows = [
            {"id": "oregon-fast", "rank": 1, "ru_reachability_score": 30, "ru_feedback_total": 10},
            {"id": "ru-confirmed", "rank": 500, "ru_reachability_score": 80, "ru_feedback_total": 10},
        ]
        result = catalog_filter(rows, sort_by="recommended", limit=10)
        self.assertEqual(result[0]["id"], "ru-confirmed")
        self.assertEqual(russian_reachability_score(8, 2), 71)

    def test_public_sort_names(self) -> None:
        rows = [
            {"id": "users", "rank": 900, "ru_reachability_score": 90, "ru_feedback_total": 8, "transport_score": 10},
            {"id": "server", "rank": 1, "ru_reachability_score": 30, "ru_feedback_total": 8, "transport_score": 95},
        ]
        self.assertEqual(catalog_filter(rows, sort_by="user_rating")[0]["id"], "users")
        self.assertEqual(catalog_filter(rows, sort_by="server_rating")[0]["id"], "server")

    def test_admin_recommendation_has_highest_priority(self) -> None:
        rows = [
            {"id": "automatic", "rank": 1, "ru_reachability_score": 99, "ru_feedback_total": 100, "transport_score": 99, "ping_ms": 1},
            {"id": "admin", "rank": 999, "ru_reachability_score": 10, "ru_feedback_total": 1, "transport_score": 40, "ping_ms": 900, "admin_recommended": True},
        ]
        for sort_name in ("user_rating", "server_rating", "stability", "ping"):
            self.assertEqual(catalog_filter(rows, sort_by=sort_name)[0]["id"], "admin")


class SelectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_shared_selector_checks_ten_then_falls_back(self) -> None:
        primary = [
            {"id": f"p{i}", "server": f"p{i}.example.com", "port": 443}
            for i in range(10)
        ]
        fallback = [{"id": "fallback", "server": "ok.example.com", "port": 443}]

        async def check(host: str, port: int) -> int | None:
            return 50 if host == "ok.example.com" else None

        result = await select_first_reachable(primary, fallback, check)
        self.assertEqual(result.proxy["id"], "fallback")
        self.assertEqual(len(result.checked_unreachable), 10)


class AuthTests(unittest.TestCase):
    def test_new_password_format_and_legacy_verification(self) -> None:
        stored = hash_password("correct horse battery staple")
        self.assertTrue(verify_password("correct horse battery staple", stored))
        self.assertFalse(password_needs_rehash(stored))

        salt = bytes(range(32))
        key = hashlib.pbkdf2_hmac(
            "sha256", b"legacy-password", salt, LEGACY_PBKDF2_ITERS
        )
        legacy = f"{binascii.hexlify(salt).decode()}:{binascii.hexlify(key).decode()}"
        self.assertTrue(verify_password("legacy-password", legacy))
        self.assertTrue(password_needs_rehash(legacy))


class PersonalizationTests(unittest.TestCase):
    def test_mobile_constrained_profile_prefers_stable_faketls(self) -> None:
        profile = normalize_client_profile({
            "device": "mobile",
            "network": "cellular",
            "effective_type": "3g",
            "rtt_ms": 300,
            "downlink_mbps": 1.2,
            "save_data": True,
        })
        candidates = [
            {"id": "plain", "secret": CORE, "transport_score": 90, "ru_reachability_score": 65, "stability": 70, "ping_ms": 180},
            {"id": "tls", "secret": FAKE_TLS, "transport_score": 80, "ru_reachability_score": 70, "stability": 98, "ping_ms": 100},
        ]
        ranked = personalize_proxies(candidates, profile, user_id=42)
        self.assertEqual(ranked[0]["id"], "tls")
        self.assertTrue(ranked[0]["match_reasons"])

    def test_invalid_profile_values_are_normalized(self) -> None:
        profile = normalize_client_profile({"device": "watch", "rtt_ms": 999999})
        self.assertEqual(profile.device, "unknown")
        self.assertEqual(profile.rtt_ms, 5000)


if __name__ == "__main__":
    unittest.main()
