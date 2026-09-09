"""
r2-symbol-importer: Streamlined Symbol & Type Acquisition Pipeline for radare2 & iaito.
"""

from r2_symbol_importer.core.pipeline import SymbolPipeline, ExtractionResult
from r2_symbol_importer.core.parser import SymbolExtractor

__version__ = "0.1.0"
__all__ = ["SymbolPipeline", "ExtractionResult", "SymbolExtractor"]
