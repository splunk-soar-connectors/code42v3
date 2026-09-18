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
import logging
import unittest
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import phantom.app as phantom
import requests

from code42v3_connector import Code42V3Connector
from code42v3_on_poll import Code42v3OnPoll
from code42v3_utils import _quote_path_segment


class PollPersistenceTest(unittest.TestCase):
    @staticmethod
    def _session(session_id, begin_time="2026-01-01T00:00:00Z"):
        return SimpleNamespace(
            session_id=session_id,
            begin_time=begin_time,
            last_updated=begin_time,
        )

    @staticmethod
    def _page(total_count, sessions):
        return SimpleNamespace(total_count=total_count, items=sessions)

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

    @patch("code42v3_connector.requests.get")
    @patch("code42v3_connector.get_verify_ssl_setting", return_value=True)
    def test_artifact_lookup_returns_none_for_404(self, _verify_ssl, get):
        response = Mock(status_code=404)
        get.return_value = response
        response.raise_for_status.side_effect = requests.HTTPError(response=response)
        connector = Code42V3Connector()
        connector.get_phantom_base_url = Mock(return_value="https://soar.example/")
        connector.get_asset_id = Mock(return_value="1")
        connector.debug_print = Mock()

        self.assertIsNone(connector.artifact_exists(1, "event-1"))

    @patch("code42v3_connector.requests.get")
    @patch("code42v3_connector.get_verify_ssl_setting", return_value=True)
    def test_container_lookup_returns_none_for_404(self, _verify_ssl, get):
        response = Mock(status_code=404)
        get.return_value = response
        response.raise_for_status.side_effect = requests.HTTPError(response=response)
        connector = Code42V3Connector()
        connector.get_phantom_base_url = Mock(return_value="https://soar.example/")

        self.assertIsNone(connector._get_container(1))

    def test_bounded_json_uses_streaming_sdk_session(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.status_code = 200
        response.headers = {}
        response.iter_content.return_value = [b'{"ok":', b" true}"]
        client = Mock()
        client.session.get.return_value = response
        poller = Code42v3OnPoll(Mock(), client, {})

        self.assertEqual(poller._get_bounded_json("/v1/sessions", params={"page_size": 1}), {"ok": True})
        client.session.get.assert_called_once_with(
            "/v1/sessions",
            params={"page_size": 1},
            timeout=(10, 60),
            stream=True,
            allow_redirects=False,
        )

    def test_bounded_json_rejects_redirect_without_reading_body(self):
        response = Mock(status_code=302)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        client = Mock()
        client.session.get.return_value = response
        poller = Code42v3OnPoll(Mock(), client, {})

        with self.assertRaisesRegex(ValueError, "Redirect responses are not allowed"):
            poller._get_bounded_json("/v1/sessions")

        response.iter_content.assert_not_called()

    @patch("code42v3_connector.incydr.Client")
    def test_incydr_client_disables_response_body_debug_logging(self, client):
        client_secret = object()
        sdk_secret = Mock()
        sdk_secret.get_secret_value.return_value = str(object())
        sdk_client = client.return_value
        sdk_client.settings.api_client_id = "client-id"
        sdk_client.settings.api_client_secret = sdk_secret
        response = Mock(status_code=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.headers = {}
        response.iter_content.return_value = [
            json.dumps(
                {
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "access_token": str(object()),
                }
            ).encode()
        ]
        sdk_client.session.post.return_value = response
        connector = Code42V3Connector()
        connector._base_url = "https://api.example"
        connector._client_id = "client-id"
        connector._client_secret = client_secret

        connector._create_incydr_client()

        client.assert_called_once_with(
            url="https://api.example",
            api_client_id="client-id",
            api_client_secret=client_secret,
            log_level=logging.WARNING,
            skip_auth=True,
        )
        sdk_client.session.post.assert_called_once()

    def test_incydr_oauth_rejects_redirect_without_reading_body(self):
        sdk_client = Mock()
        sdk_client.settings.api_client_id = "client-id"
        sdk_client.settings.api_client_secret.get_secret_value.return_value = str(object())
        response = Mock(status_code=302)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        sdk_client.session.post.return_value = response
        connector = Code42V3Connector()
        connector._base_url = "https://api.example"
        connector._client_id = "client-id"
        connector._client_secret = object()

        with patch("code42v3_connector.incydr.Client", return_value=sdk_client):
            with self.assertRaisesRegex(RuntimeError, "Redirect responses are not allowed"):
                connector._create_incydr_client()

        response.iter_content.assert_not_called()

    @patch("code42v3_connector.MAX_AUTH_RESPONSE_BYTES", 4)
    def test_incydr_oauth_rejects_oversized_stream(self):
        sdk_client = Mock()
        sdk_client.settings.api_client_id = "client-id"
        sdk_client.settings.api_client_secret.get_secret_value.return_value = str(object())
        response = Mock(status_code=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.headers = {}
        response.iter_content.return_value = [b"12345"]
        sdk_client.session.post.return_value = response
        connector = Code42V3Connector()
        connector._base_url = "https://api.example"
        connector._client_id = "client-id"
        connector._client_secret = object()

        with patch("code42v3_connector.incydr.Client", return_value=sdk_client):
            with self.assertRaisesRegex(ValueError, "OAuth response exceeded"):
                connector._create_incydr_client()

    def test_select_session_window_bounds_an_overfull_range(self):
        poller = Code42v3OnPoll(Mock(), Mock(), {})
        start = datetime(2026, 1, 1, tzinfo=UTC)
        end = start + timedelta(days=1)

        def get_page(_start, candidate_end, _severities, _page_num):
            count = 10_001 if candidate_end == end else 1
            return self._page(count, [self._session("oldest")])

        poller._get_sessions_page = Mock(side_effect=get_page)

        window_end, page, limited = poller._select_session_window(start, end, [1])

        self.assertTrue(limited)
        self.assertLess(window_end, end)
        self.assertEqual(page.total_count, 1)

    def test_collect_session_window_accepts_stable_pagination(self):
        poller = Code42v3OnPoll(Mock(), Mock(), {})
        sessions = [self._session("a"), self._session("b")]
        poller._get_sessions_page = Mock(side_effect=[self._page(2, sessions), self._page(2, [])])

        result = poller._collect_session_window(Mock(), Mock(), [1], 2)

        self.assertEqual([session.session_id for session in result], ["a", "b"])

    def test_collect_session_window_rejects_changed_total_count(self):
        poller = Code42v3OnPoll(Mock(), Mock(), {})
        poller._get_sessions_page = Mock(return_value=self._page(2, [self._session("a")]))

        with self.assertRaisesRegex(ValueError, "totalCount changed"):
            poller._collect_session_window(Mock(), Mock(), [1], 1)

    def test_get_bounded_sessions_rejects_order_changes_between_passes(self):
        poller = Code42v3OnPoll(Mock(), Mock(), {})
        first_page = self._page(2, [self._session("a"), self._session("b")])
        poller._select_session_window = Mock(return_value=(Mock(), first_page, False))
        poller._collect_session_window = Mock(
            side_effect=[
                [self._session("a"), self._session("b")],
                [self._session("b"), self._session("a")],
            ]
        )

        with self.assertRaisesRegex(ValueError, "changed between verification passes"):
            poller._get_bounded_sessions(Mock(), Mock(), [1])

    def test_collect_session_window_rejects_duplicate_session_ids(self):
        poller = Code42v3OnPoll(Mock(), Mock(), {})
        duplicate_sessions = [self._session("a"), self._session("a")]
        poller._get_sessions_page = Mock(return_value=self._page(2, duplicate_sessions))

        with self.assertRaisesRegex(ValueError, "unique progress"):
            poller._collect_session_window(Mock(), Mock(), [1], 2)

    def test_failed_session_blocks_checkpoint_advancement(self):
        connector = Mock()
        connector.get_config.return_value = {
            "overlap_hours": 0,
            "severity_filter": "low",
        }
        connector._get_existing_container_id_for_sdi.side_effect = [
            RuntimeError("lookup failed"),
            None,
        ]
        action_result = Mock()
        action_result.set_status.side_effect = lambda status, *_args: status
        poller = Code42v3OnPoll(connector, Mock(), {})
        poller._get_date_parameters = Mock(
            return_value=(
                datetime(2026, 1, 1, tzinfo=UTC),
                datetime(2026, 1, 2, tzinfo=UTC),
                None,
            )
        )
        poller._get_bounded_sessions = Mock(
            return_value=(
                [self._session("failed"), self._session("succeeded", "2026-01-01T01:00:00Z")],
                False,
            )
        )
        poller._get_session_events = Mock(return_value=[])
        poller._create_or_update_container = Mock(return_value=1)
        poller._save_artifacts_from_file_event = Mock()
        poller._save_last_time = Mock()

        status = poller.handle_on_poll({}, action_result)

        self.assertEqual(status, phantom.APP_ERROR)
        poller._save_last_time.assert_not_called()

    def test_path_segment_policy_rejects_empty_and_dot_segments(self):
        for session_id in ("", ".", ".."):
            with self.subTest(session_id=session_id):
                with self.assertRaisesRegex(ValueError, "non-empty strings"):
                    _quote_path_segment(session_id)

    def test_path_segment_policy_encodes_separators_and_encoded_traversal(self):
        self.assertEqual(_quote_path_segment("session/id"), "session%2Fid")
        self.assertEqual(_quote_path_segment("%2e%2e"), "%252e%252e")

    def test_source_id_uses_path_segment_policy(self):
        connector = Mock()
        connector.get_config.return_value = {"severity_filter": "low"}
        action_result = Mock()
        action_result.set_status.side_effect = lambda status, *_args: status
        poller = Code42v3OnPoll(connector, Mock(), {})
        poller._get_bounded_json = Mock(return_value={})
        poller._get_session_events = Mock(return_value=[])
        poller._create_or_update_container = Mock(return_value=1)
        poller._save_artifacts_from_file_event = Mock()

        for session_id in ("", ".", ".."):
            with self.subTest(session_id=session_id):
                status = poller.handle_on_poll({"source_id": session_id}, action_result)
                self.assertEqual(status, phantom.APP_ERROR)
        poller._get_bounded_json.assert_not_called()

        with patch("code42v3_on_poll.Session.parse_obj", return_value=self._session("returned-session")):
            for session_id, encoded_session_id in (("session/id", "session%2Fid"), ("%2e%2e", "%252e%252e")):
                with self.subTest(session_id=session_id):
                    poller._get_bounded_json.reset_mock()
                    poller.handle_on_poll({"source_id": session_id}, action_result)
                    poller._get_bounded_json.assert_called_once_with(f"/v1/sessions/{encoded_session_id}")

    def test_source_id_artifact_failure_becomes_action_failure(self):
        connector = Mock()
        connector.get_config.return_value = {"severity_filter": "low"}
        action_result = Mock()
        action_result.set_status.side_effect = lambda status, *_args: status
        poller = Code42v3OnPoll(connector, Mock(), {})
        poller._get_bounded_json = Mock(return_value={})
        poller._get_session_events = Mock(return_value=[])
        poller._create_or_update_container = Mock(return_value=1)
        poller._save_artifacts_from_file_event = Mock(side_effect=RuntimeError("artifact lookup failed"))

        with patch("code42v3_on_poll.Session.parse_obj", return_value=self._session("session-1")):
            status = poller.handle_on_poll({"source_id": "session-1"}, action_result)

        self.assertEqual(status, phantom.APP_ERROR)
        self.assertIn("artifact lookup failed", action_result.set_status.call_args.args[1])

    def test_disappearing_container_becomes_action_failure(self):
        connector = Mock()
        connector.get_config.return_value = {"overlap_hours": 0, "severity_filter": "low"}
        connector._get_existing_container_id_for_sdi.return_value = 1
        connector._get_container.return_value = None
        action_result = Mock()
        action_result.set_status.side_effect = lambda status, *_args: status
        poller = Code42v3OnPoll(connector, Mock(), {})
        poller._get_date_parameters = Mock(
            return_value=(
                datetime(2026, 1, 1, tzinfo=UTC),
                datetime(2026, 1, 2, tzinfo=UTC),
                None,
            )
        )
        poller._get_bounded_sessions = Mock(return_value=([self._session("session-1")], False))
        poller._save_last_time = Mock()

        status = poller.handle_on_poll({}, action_result)

        self.assertEqual(status, phantom.APP_ERROR)
        poller._save_last_time.assert_not_called()

    def test_malformed_container_update_time_blocks_checkpoint(self):
        connector = Mock()
        connector.get_config.return_value = {"overlap_hours": 0, "severity_filter": "low"}
        connector._get_existing_container_id_for_sdi.return_value = 1
        connector._get_container.return_value = {"container_update_time": "not-a-timestamp"}
        action_result = Mock()
        action_result.set_status.side_effect = lambda status, *_args: status
        poller = Code42v3OnPoll(connector, Mock(), {})
        poller._get_date_parameters = Mock(
            return_value=(
                datetime(2026, 1, 1, tzinfo=UTC),
                datetime(2026, 1, 2, tzinfo=UTC),
                None,
            )
        )
        poller._get_bounded_sessions = Mock(return_value=([self._session("session-1")], False))
        poller._get_session_events = Mock(return_value=[])
        poller._save_artifacts_from_file_event = Mock()
        poller._save_last_time = Mock()

        status = poller.handle_on_poll({}, action_result)

        self.assertEqual(status, phantom.APP_ERROR)
        poller._save_artifacts_from_file_event.assert_not_called()
        poller._save_last_time.assert_not_called()

    def test_missing_container_update_time_forces_update_and_blocks_on_failure(self):
        connector = Mock()
        connector.get_config.return_value = {"overlap_hours": 0, "severity_filter": "low"}
        connector._get_existing_container_id_for_sdi.return_value = 1
        connector._get_container.return_value = {}
        action_result = Mock()
        action_result.set_status.side_effect = lambda status, *_args: status
        poller = Code42v3OnPoll(connector, Mock(), {})
        poller._get_date_parameters = Mock(
            return_value=(
                datetime(2026, 1, 1, tzinfo=UTC),
                datetime(2026, 1, 2, tzinfo=UTC),
                None,
            )
        )
        poller._get_bounded_sessions = Mock(return_value=([self._session("session-1")], False))
        poller._get_session_events = Mock(return_value=[])
        poller._create_or_update_container = Mock(return_value=None)
        poller._save_artifacts_from_file_event = Mock()
        poller._save_last_time = Mock()

        status = poller.handle_on_poll({}, action_result)

        self.assertEqual(status, phantom.APP_ERROR)
        poller._create_or_update_container.assert_called_once()
        poller._save_artifacts_from_file_event.assert_not_called()
        poller._save_last_time.assert_not_called()

    def test_container_save_exception_becomes_action_failure(self):
        connector = Mock()
        connector.get_config.return_value = {"overlap_hours": 0, "severity_filter": "low"}
        connector._get_existing_container_id_for_sdi.return_value = None
        connector.save_container.side_effect = RuntimeError("platform unavailable")
        action_result = Mock()
        action_result.set_status.side_effect = lambda status, *_args: status
        poller = Code42v3OnPoll(connector, Mock(), {})
        poller._get_date_parameters = Mock(
            return_value=(
                datetime(2026, 1, 1, tzinfo=UTC),
                datetime(2026, 1, 2, tzinfo=UTC),
                None,
            )
        )
        poller._get_bounded_sessions = Mock(return_value=([self._session("session-1")], False))
        poller._get_session_events = Mock(return_value=[])
        poller._create_container_payload = Mock(return_value={})
        poller._save_last_time = Mock()

        status = poller.handle_on_poll({}, action_result)

        self.assertEqual(status, phantom.APP_ERROR)
        poller._save_last_time.assert_not_called()

    @patch("code42v3_on_poll.FileEventsPage.parse_obj")
    def test_api_session_id_uses_path_segment_policy(self, parse_page):
        parse_page.return_value = SimpleNamespace(file_events=[], next_pg_token=None)
        poller = Code42v3OnPoll(Mock(), Mock(), {})
        poller._get_bounded_json = Mock(return_value={"queryResult": {}})

        for session_id in ("", ".", ".."):
            with self.subTest(session_id=session_id):
                with self.assertRaisesRegex(ValueError, "non-empty strings"):
                    poller._get_session_events(session_id, 10)
        poller._get_bounded_json.assert_not_called()

        for session_id, encoded_session_id in (("session/id", "session%2Fid"), ("%2e%2e", "%252e%252e")):
            with self.subTest(session_id=session_id):
                poller._get_bounded_json.reset_mock()
                poller._get_session_events(session_id, 10)
                poller._get_bounded_json.assert_called_once_with(f"/v1/sessions/{encoded_session_id}/events", params=None)


if __name__ == "__main__":
    unittest.main()
