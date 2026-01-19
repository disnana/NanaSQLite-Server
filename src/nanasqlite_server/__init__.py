"""
NanaSQLite Server: A secure QUIC-based RPC server for NanaSQLite.
"""

from .server import main, main_sync

__version__ = "1.0.1dev1"
__author__ = "NanaSQLite-Project"
__all__ = ["main", "main_sync"]
