import hashlib
import importlib.util
from pathlib import Path
import unittest
from urllib.parse import quote_plus

path = Path(__file__).resolve().parents[1] / "scripts/correlate-business-trace.py"
spec = importlib.util.spec_from_file_location("correlate", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CorrelationTests(unittest.TestCase):
    def fixtures(self):
        values = {"x-sign": "fixture+/%2B", "x-mini-wua": "fixture-mini", "x-umt": "shared-device"}
        trace = {"api": "mtop.fixture.cart", "output_sha256": {
            k: hashlib.sha256(v.encode()).hexdigest() for k, v in values.items()}}
        session = {"id": 7, "status": 419, "url": "https://example.invalid/gw/mtop.fixture.cart/1.0/",
                   "request_headers": {k.upper(): [quote_plus(v)] for k, v in values.items()}}
        return trace, session

    def test_one_decode_and_case_insensitive_headers(self):
        trace, session = self.fixtures()
        result = module.correlate([trace], [session])[0]
        self.assertTrue(result["matches"][0]["all_recorded_fields_match"])

    def test_other_api_cannot_match_same_signature(self):
        trace, session = self.fixtures()
        session["url"] = session["url"].replace("fixture.cart", "fixture.other")
        self.assertEqual(module.correlate([trace], [session])[0]["candidate_count"], 0)

    def test_shared_device_without_signature_is_not_a_match(self):
        trace, session = self.fixtures()
        del trace["output_sha256"]["x-sign"]
        self.assertEqual(module.correlate([trace], [session])[0]["candidate_count"], 0)

    def test_replays_remain_ambiguous_and_factor_changes_are_visible(self):
        trace, session = self.fixtures()
        second = dict(session, id=8, request_headers=dict(session["request_headers"]))
        second["request_headers"]["X-MINI-WUA"] = "different"
        result = module.correlate([trace], [session, second])[0]
        self.assertEqual(result["candidate_count"], 2)
        self.assertEqual(result["matches"][1]["different_or_missing_fields"], ["x-mini-wua"])

    def test_eight_fields_and_first_divergence_diff(self):
        diff_path = Path(__file__).resolve().parents[1] / "scripts/diff-business-traces.py"
        diff_spec = importlib.util.spec_from_file_location("diff_traces", diff_path)
        diff_mod = importlib.util.module_from_spec(diff_spec)
        diff_spec.loader.exec_module(diff_mod)

        ok_trace = {
            "api": "mtop.relationrecommend.wirelessrecommend.recommend",
            "output_fields": {
                "x-sign": {"present": True, "length": 10, "sha256": "aaa"},
                "x-gst": {"present": False, "length": 0},
            },
            "native": {
                "append_calls": 2,
                "records": [{"caller_offset": 100, "source_length": 16}, {"caller_offset": 200, "source_length": 32}],
                "events": [{"caller_offset": 50, "kind": "sg_prop", "target": "ro.product.model", "ret": 6}],
            },
        }
        fail_trace = {
            "api": "mtop.trade.query.bag",
            "output_fields": {
                "x-sign": {"present": True, "length": 10, "sha256": "bbb"},
                "x-gst": {"present": True, "length": 24, "sha256": "ccc"},
            },
            "native": {
                "append_calls": 2,
                "records": [{"caller_offset": 100, "source_length": 16}, {"caller_offset": 300, "source_length": 18}],
                "events": [
                    {"caller_offset": 50, "kind": "sg_prop", "target": "ro.product.model", "ret": 6},
                    {"caller_offset": 60, "kind": "sg_open", "target": "/proc/self/maps", "ret": 0},
                ],
            },
        }
        report = diff_mod.diff_traces(ok_trace, fail_trace)
        self.assertIn("x-gst", report["field_diffs"])
        self.assertEqual(report["first_append_divergence"]["index"], 1)
        self.assertEqual(report["first_event_divergence"]["index"], 1)


if __name__ == "__main__":
    unittest.main()
