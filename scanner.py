"""
Backward-compatible entry point: delegates to ``scanner_controller.run_scan``.
"""

from scanner_controller import run_scan

__all__ = ["run_scan"]
