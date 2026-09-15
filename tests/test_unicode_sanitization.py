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
import json
import unicodedata
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

from code42v3_on_poll import Code42v3OnPoll, _map_event_to_cef
from code42v3_utils import _strip_unicode_format_controls


class UnicodeSanitizationTest(unittest.TestCase):
    MALICIOUS_FILE_NAME = "invoice_2026\u200b_\u202efdp.scr"
    SANITIZED_FILE_NAME = "invoice_2026_fdp.scr"

    @staticmethod
    def _file_event():
        observed_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        raw_data = {
            "file": {"name": UnicodeSanitizationTest.MALICIOUS_FILE_NAME},
            "event": {"id": "event\u200b-1"},
        }
        return SimpleNamespace(
            timestamp=observed_at,
            event=SimpleNamespace(
                id="event\u200b-1",
                action="file-created",
                inserted=observed_at,
                ingested=observed_at,
                shareType=[],
                vector="UPLOADED",
                observer=None,
                detector_display_name="Endpoint monitor",
            ),
            file=SimpleNamespace(
                category="Document",
                cloud_drive_id=None,
                name=UnicodeSanitizationTest.MALICIOUS_FILE_NAME,
                size_in_bytes=24576,
                created=observed_at,
                modified=observed_at,
                hash=None,
                directory="C:/Users/j.doe/Downloads/",
                url=None,
            ),
            source=SimpleNamespace(
                email=None,
                domain="corp.example",
                name="FIN-\u202eWKSTN-07",
                ip="10.20.30.44",
                account_name=None,
                category=None,
                tabs=None,
                user=None,
                removable_media=None,
            ),
            destination=SimpleNamespace(
                ip=None,
                account_name="personal-gdrive",
                name="Google Drive",
                category="Cloud Storage",
                email=None,
                user=SimpleNamespace(email=["target\u200b@example.com"]),
                tabs=None,
                removable_media=None,
            ),
            process=SimpleNamespace(executable="process\u200b.exe", owner="owner\u200c"),
            risk=SimpleNamespace(severity="HIGH", score=9, indicators=[], trust_reason=None),
            user=SimpleNamespace(device_uid="dev-1", id="user-1", email="j.doe\ufeff@corp.example"),
            json=Mock(return_value=json.dumps(raw_data)),
        )

    def test_strip_unicode_format_controls_only_removes_cf_characters(self):
        controls = "\u202e\u202d\u200b\u200c\ufeff"
        self.assertTrue(all(unicodedata.category(char) == "Cf" for char in controls))
        self.assertEqual(
            _strip_unicode_format_controls(f"caf\u00e9 \U0001f600 {controls} file.txt"),
            "caf\u00e9 \U0001f600  file.txt",
        )
        self.assertEqual(_strip_unicode_format_controls(42), 42)

    def test_event_cef_strings_strip_unicode_format_controls(self):
        cef = _map_event_to_cef(self._file_event())

        self.assertEqual(cef["fname"], self.SANITIZED_FILE_NAME)
        self.assertEqual(cef["filePath"], f"C:/Users/j.doe/Downloads/{self.SANITIZED_FILE_NAME}")
        self.assertEqual(cef["shost"], "FIN-WKSTN-07")
        self.assertEqual(cef["suser"], "j.doe@corp.example")
        self.assertEqual(cef["duser"], "target@example.com")
        self.assertEqual(cef["sproc"], "process.exe")
        self.assertEqual(cef["spriv"], "owner")
        for value in cef.values():
            if isinstance(value, str):
                self.assertFalse(any(unicodedata.category(char) == "Cf" for char in value))

    def test_container_fields_are_sanitized_but_raw_values_are_preserved(self):
        raw_summary = f"j.doe uploaded {self.MALICIOUS_FILE_NAME}"
        raw_description = "personal\u200b cloud\u202e upload"
        raw_session_id = "session\u200b-1"
        session_details = SimpleNamespace(
            activitySummary=raw_summary,
            context_summary=raw_description,
            session_id=raw_session_id,
            type="code42Alert",
            scores=[SimpleNamespace(severity=3)],
            json=Mock(return_value=json.dumps({"activitySummary": raw_summary})),
        )
        connector = Mock()
        connector.get_config.return_value = {"ingest": {"container_label": "events"}}
        payload = Code42v3OnPoll(connector, Mock(), {})._create_container_payload(session_details)

        self.assertEqual(payload["name"], f"j.doe uploaded {self.SANITIZED_FILE_NAME}")
        self.assertEqual(payload["description"], "personal cloud upload")
        self.assertEqual(payload["source_data_identifier"], raw_session_id)
        self.assertEqual(payload["data"]["activitySummary"], raw_summary)

    def test_container_uses_sanitized_fallback_for_an_empty_summary(self):
        raw_session_id = "session\u200b-1"
        session_details = SimpleNamespace(
            activitySummary="\u200b\u202e",
            context_summary=None,
            session_id=raw_session_id,
            type="code42Alert",
            scores=[SimpleNamespace(severity=3)],
            json=Mock(return_value=json.dumps({"sessionId": raw_session_id})),
        )
        connector = Mock()
        connector.get_config.return_value = {"ingest": {"container_label": "events"}}
        payload = Code42v3OnPoll(connector, Mock(), {})._create_container_payload(session_details)

        self.assertEqual(payload["name"], "Code42 session session-1")
        self.assertIsNone(payload["description"])
        self.assertEqual(payload["source_data_identifier"], raw_session_id)

    def test_artifact_cef_is_sanitized_but_raw_values_are_preserved(self):
        file_event = self._file_event()
        payload = Code42v3OnPoll(Mock(), Mock(), {})._create_artifact_payload(42, file_event)

        self.assertEqual(payload["cef"]["fname"], self.SANITIZED_FILE_NAME)
        self.assertEqual(payload["source_data_identifier"], "event\u200b-1")
        self.assertEqual(payload["data"]["file"]["name"], self.MALICIOUS_FILE_NAME)


if __name__ == "__main__":
    unittest.main()
