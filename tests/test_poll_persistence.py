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
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

import phantom.app as phantom

from code42v3_connector import Code42V3Connector
from code42v3_on_poll import Code42v3OnPoll


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

    def test_select_session_window_bounds_an_overfull_range(self):
        poller = Code42v3OnPoll(Mock(), Mock(), {})
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
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
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                datetime(2026, 1, 2, tzinfo=timezone.utc),
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


if __name__ == "__main__":
    unittest.main()
