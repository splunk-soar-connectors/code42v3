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
import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import phantom.app as phantom
from requests import HTTPError

from code42v3_connector import (
    Code42FileHashMismatchError,
    Code42FileTooLargeError,
    Code42V3Connector,
)
from code42v3_consts import HUNT_FILE_DOWNLOAD_CHUNK_SIZE, MAX_HUNT_FILE_BYTES


class HuntFileTest(unittest.TestCase):
    @staticmethod
    def _response(chunks, content_length=None):
        response = Mock()
        response.headers = {}
        if content_length is not None:
            response.headers["Content-Length"] = str(content_length)
        response.iter_content.return_value = chunks
        return response

    @staticmethod
    def _connector(response):
        connector = Code42V3Connector()
        stream_file = Mock(return_value=response)
        connector._client = SimpleNamespace(files=SimpleNamespace(v1=SimpleNamespace(stream_file_by_sha256=stream_file)))
        return connector, stream_file

    @staticmethod
    def _action_result():
        action_result = Mock()
        action_result.set_status.side_effect = lambda status, *_args: status
        return action_result

    def test_matching_hash_returns_content_and_verified_hash(self):
        content = b"verified file content"
        expected_hash = hashlib.sha256(content).hexdigest()
        response = self._response([content[:8], b"", content[8:]], len(content))
        connector, stream_file = self._connector(response)

        file_content, verified_hash = connector._get_file_content(expected_hash.upper())

        self.assertEqual(file_content, content)
        self.assertEqual(verified_hash, expected_hash)
        stream_file.assert_called_once_with(sha256=expected_hash.upper())
        response.iter_content.assert_called_once_with(chunk_size=HUNT_FILE_DOWNLOAD_CHUNK_SIZE)
        response.close.assert_called_once_with()

    def test_mismatched_hash_reports_both_hashes_and_closes_response(self):
        content = b"unexpected file content"
        expected_hash = hashlib.sha256(b"expected file content").hexdigest()
        actual_hash = hashlib.sha256(content).hexdigest()
        response = self._response([content])
        connector, _stream_file = self._connector(response)

        with self.assertRaises(Code42FileHashMismatchError) as raised:
            connector._get_file_content(expected_hash)

        self.assertIn(expected_hash, str(raised.exception))
        self.assertIn(actual_hash, str(raised.exception))
        response.close.assert_called_once_with()

    def test_declared_oversized_file_is_rejected_before_streaming(self):
        response = self._response([], MAX_HUNT_FILE_BYTES + 1)
        connector, _stream_file = self._connector(response)

        with self.assertRaises(Code42FileTooLargeError):
            connector._get_file_content(hashlib.sha256(b"").hexdigest())

        response.iter_content.assert_not_called()
        response.close.assert_called_once_with()

    @patch("code42v3_connector.MAX_HUNT_FILE_BYTES", 4)
    def test_streamed_file_is_rejected_when_it_crosses_size_limit(self):
        response = self._response([b"abc", b"de"])
        connector, _stream_file = self._connector(response)

        with self.assertRaises(Code42FileTooLargeError):
            connector._get_file_content(hashlib.sha256(b"abcde").hexdigest())

        response.close.assert_called_once_with()

    @patch("code42v3_connector.MAX_HUNT_FILE_BYTES", 4)
    def test_file_exactly_at_size_limit_is_accepted(self):
        content = b"abcd"
        expected_hash = hashlib.sha256(content).hexdigest()
        response = self._response([b"ab", b"cd"])
        connector, _stream_file = self._connector(response)

        file_content, verified_hash = connector._get_file_content(expected_hash)

        self.assertEqual(file_content, content)
        self.assertEqual(verified_hash, expected_hash)
        response.close.assert_called_once_with()

    @patch("code42v3_connector.Vault.create_attachment")
    def test_hash_mismatch_does_not_create_vault_attachment(self, create_attachment):
        content = b"unexpected file content"
        expected_hash = hashlib.sha256(b"expected file content").hexdigest()
        response = self._response([content])
        connector, _stream_file = self._connector(response)
        action_result = self._action_result()

        status = connector._handle_hunt_file({"file_hash": expected_hash}, action_result)

        self.assertEqual(status, phantom.APP_ERROR)
        create_attachment.assert_not_called()
        status_message = action_result.set_status.call_args.args[1]
        self.assertIn(expected_hash, status_message)
        self.assertIn(hashlib.sha256(content).hexdigest(), status_message)

    @patch("code42v3_connector.Vault.create_attachment")
    def test_verified_file_is_added_to_vault_with_hash_in_summary(self, create_attachment):
        content = b"verified file content"
        expected_hash = hashlib.sha256(content).hexdigest()
        response = self._response([content])
        connector, _stream_file = self._connector(response)
        connector.get_container_id = Mock(return_value=42)
        create_attachment.return_value = {"succeeded": True, "vault_id": "vault-id"}
        action_result = self._action_result()

        status = connector._handle_hunt_file({"file_hash": expected_hash}, action_result)

        self.assertEqual(status, phantom.APP_SUCCESS)
        create_attachment.assert_called_once_with(content, 42, file_name=expected_hash)
        action_result.update_summary.assert_called_once_with(
            {
                "file_name": expected_hash,
                "container_id": 42,
                "vault_id": "vault-id",
                "verified_sha256": expected_hash,
            }
        )

    def test_http_error_is_preserved_and_response_is_closed(self):
        expected_hash = hashlib.sha256(b"expected file content").hexdigest()
        response = self._response([])
        http_error = HTTPError("not found")
        http_error.response = Mock(status_code=404, text="not retained")
        response.raise_for_status.side_effect = http_error
        connector, _stream_file = self._connector(response)
        action_result = self._action_result()

        status = connector._handle_hunt_file({"file_hash": expected_hash}, action_result)

        self.assertEqual(status, phantom.APP_ERROR)
        self.assertIn("unavailable", action_result.set_status.call_args.args[1])
        response.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
