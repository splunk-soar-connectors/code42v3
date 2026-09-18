# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import unicodedata
import urllib.parse


def _strip_unicode_format_controls(value):
    """Remove Unicode format-control characters from a string."""
    if not isinstance(value, str):
        return value

    return "".join(char for char in value if unicodedata.category(char) != "Cf")


def _validate_identifier(value):
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise ValueError("Path identifiers must be non-empty strings and cannot be dot segments")

    return value


def _quote_path_segment(value):
    return urllib.parse.quote(_validate_identifier(value), safe="")
