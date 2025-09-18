"""VCDIFF Python Implementation

A Python implementation of VCDIFF (RFC 3284) delta compression format.

Copyright 2025 Ably Realtime Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from .decoder import Decoder, decode, parse_delta
from .exceptions import (
    VCDIFFError,
    InvalidMagicError,
    InvalidVersionError,
    InvalidFormatError,
    CorruptedDataError,
    InvalidChecksumError,
)
from .types import InstructionType

__version__ = "0.1.0"
__all__ = [
    "Decoder",
    "decode",
    "parse_delta",
    "InstructionType",
    "VCDIFFError",
    "InvalidMagicError",
    "InvalidVersionError",
    "InvalidFormatError",
    "CorruptedDataError",
    "InvalidChecksumError",
]