"""Tests for the Prompt Guard core. Run: python -m pytest -q  (or python tests/test_promptguard.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from promptguard.detectors import Detector
from promptguard.engine import Engine

SAMPLE = (
    "Here's my code, why does deploy fail?\n"
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    "aws_key = AKIAIOSFODNN7EXAMPLE\n"
    "openai_key = sk-proj-abcdefghij1234567890ABCDEFqrstuvwx\n"
    "contact me at jane.doe@acme.com or 415-555-0132\n"
    "card 4111 1111 1111 1111 on file\n"
)


def test_detects_core_categories():
    f = Detector().scan(SAMPLE)
    labels = {x.label for x in f}
    assert "AWS Access Key ID" in labels
    assert "AWS Secret Access Key" in labels
    assert "OpenAI API Key" in labels
    assert "Email Address" in labels
    assert "Credit Card Number" in labels   # Luhn-valid test card
    assert Detector.max_severity(f) == "CRITICAL"


def test_reversible_round_trip():
    eng = Engine()
    res = eng.inspect(SAMPLE, destination="chat.openai.com", surface="browser")
    # the redacted prompt must NOT contain the raw secrets
    assert "AKIAIOSFODNN7EXAMPLE" not in res.redacted
    assert "wJalrXUtnFEMI" not in res.redacted
    assert "«PG:" in res.redacted
    # restoring a (simulated) model response re-inserts the originals
    answer = "Your key «PG:AWS_ACCESS_KEY_ID:1» is fine; rotate it anyway."
    restored = eng.restore(answer, res.vault)
    assert "AKIAIOSFODNN7EXAMPLE" in restored


def test_evidence_has_controls_and_no_raw_secret():
    res = Engine().inspect(SAMPLE)
    ev = res.event
    assert ev["cataam_import_version"] == "1.0"
    assert ev["event_type"] == "ai_egress_control"
    # the moat: mapped, auditor-ready controls present
    assert "iso42001" in ev["controls"]
    assert "eu_ai_act" in ev["controls"]
    assert any("Art.12" in c for c in ev["controls"]["eu_ai_act"])
    # privacy: evidence must never carry the raw secret
    blob = str(ev)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "wJalrXUtnFEMI" not in blob


def test_clean_prompt_is_untouched():
    res = Engine().inspect("How do I reverse a linked list in Python?")
    assert res.clean
    assert res.redacted == res.original


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print(f"ok  {name}")
    print("ALL PASS")
