"""Offline static serialization evidence; never load a model."""

from .contracts import Limits
from .review import review_bytes, review_file

__all__ = ["Limits", "review_bytes", "review_file"]
__version__ = "0.1.3"
