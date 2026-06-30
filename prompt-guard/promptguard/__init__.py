"""Cataam Prompt Guard — local-first prompt hygiene.

Sift secrets, API keys and PII out of prompts before they leave for public LLMs,
reversibly (so answers stay useful), and emit Cataam-importable audit evidence
mapped to ISO 42001 / NIST AI RMF / EU AI Act.
"""
from .detectors import Detector, Finding
from .engine import Engine, GuardResult
from .vault import Vault

__version__ = "0.1.0"
__all__ = ["Detector", "Finding", "Engine", "GuardResult", "Vault"]
