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
import unittest
from unittest.mock import Mock, patch

from code42v3_connector import Code42V3Connector
from code42v3_on_poll import Code42v3OnPoll


class PollPersistenceTest(unittest.TestCase):
    def test_artifact_save_failure_raises(self):
        connector = Mock()
        connector.artifact_exists.return_value = False
        connector.save_artifacts.return_value = (False, "write failed", None)
        poller = Code42v3OnPoll(connector, Mock(), {})
        poller._create_artifact_payload = Mock(return_value={"source_data_identifier": "event-1"})
        event = Mock()
        event.event.id = "event-1"

        with self.assertRaisesRegex(RuntimeError, "write failed"):
            poller._save_artifacts_from_file_event(1, [event], 10)

    @patch("code42v3_connector.requests.post")
    @patch("code42v3_connector.get_verify_ssl_setting", return_value=True)
    def test_container_update_rejects_http_failure(self, _verify_ssl, post):
        post.return_value.raise_for_status.side_effect = RuntimeError("server error")
        connector = Code42V3Connector()
        connector.get_phantom_base_url = Mock(return_value="https://soar.example/")

        with self.assertRaisesRegex(RuntimeError, "updating container metadata"):
            connector._update_container(1, {}, "medium")


if __name__ == "__main__":
    unittest.main()
