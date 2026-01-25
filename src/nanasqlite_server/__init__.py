"""
NanaSQLite Server: A secure QUIC-based RPC server for NanaSQLite.
"""

from .server import main, main_sync

__version__ = "1.1.1dev0"
__author__ = "NanaSQLite-Project"
__all__ = ["main", "main_sync"]
