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
from unittest.mock import MagicMock, patch

from soar_sdk.abstract import SOARClient

from src.actions.connectivity import test_connectivity as check_connectivity
from src.actions.run_query import unique_column_names
from src.app import app
from src.asset import Asset
from src.views import display_query_results


class SnowflakeConnectorTest(unittest.TestCase):
    def setUp(self):
        self.connect = self.enterContext(patch("snowflake.connector.connect"))
        self.connection = self.connect.return_value
        self.cursor = self.connection.cursor.return_value
        self.asset = Asset(account="example", username="example", password="fixture")
        self.soar = MagicMock(spec=SOARClient)

    def run_action(self, identifier, **params):
        handler = app.get_actions()[identifier]
        inputs = handler.params_class.model_validate(params)
        with patch.object(app.actions_manager, "add_result") as add_result:
            status = handler(inputs, soar=self.soar, asset=self.asset)
        add_result.assert_called_once()
        result = add_result.call_args.args[0]
        assert status == result.get_status()
        return result

    def test_duplicate_column_names_keep_every_value_and_avoid_generated_name_collisions(
        self,
    ):
        description = [("NAME",), ("NAME__duplicate_2",), ("NAME",), ("NAME",)]
        names = unique_column_names(description)
        result = dict(zip(names, ("first", "existing", "second", "third"), strict=True))
        assert result == {
            "NAME": "first",
            "NAME__duplicate_2": "existing",
            "NAME__duplicate_2_1": "second",
            "NAME__duplicate_3": "third",
        }

    def test_query_keeps_dynamic_columns_alias_batches_and_summary(self):
        self.cursor.description = [("NAME",), ("NAME",), ("self",)]
        self.cursor.fetchmany.side_effect = [
            [("first", b"second", 1)],
            [("third", "fourth", 2)],
            [],
        ]
        self.cursor.rowcount = 2
        result = self.run_action(
            "run_query", query='select 1 as "self"', schema="example"
        )
        assert result.get_status()
        assert result.get_data() == [
            {"NAME": "first", "NAME__duplicate_1": "second", "self": 1},
            {"NAME": "third", "NAME__duplicate_1": "fourth", "self": 2},
        ]
        assert result.get_param() == {
            "query": 'select 1 as "self"',
            "schema": "example",
        }
        assert result.get_summary() == {"total_rows": 2}
        assert self.connect.call_args.kwargs["schema"] == "example"
        self.cursor.close.assert_called_once()
        self.connection.close.assert_called_once()

    def test_query_with_no_result_columns_has_empty_output(self):
        self.cursor.description = None
        self.cursor.rowcount = -1
        result = self.run_action("run_query", query="select 1")
        assert result.get_status()
        assert result.get_data() == []
        assert result.get_summary() == {"total_rows": 0}
        self.cursor.fetchmany.assert_not_called()

    def test_connection_and_failed_query_close_resources(self):
        check_connectivity(self.soar, self.asset)
        self.soar.set_message.assert_called_once_with("Test connectivity passed")
        self.cursor.execute.side_effect = RuntimeError("test failure")
        result = self.run_action("run_query", query="select 1")
        assert not result.get_status()
        assert result.get_message() == "SQL query failed: Error Message: test failure"
        assert self.cursor.close.call_count == 2
        assert self.connection.close.call_count == 2

    def test_show_and_describe_keep_policy_fields(self):
        self.cursor.fetchmany.side_effect = [
            [{"name": "example", "vendor_field": 1}],
            [],
            [{"name": "property", "value": None}],
            [],
        ]
        show = self.run_action("show_network_policies")
        assert show.get_data() == [{"name": "example", "vendor_field": 1}]
        assert show.get_summary() == {"total_policies": 1}
        described = self.run_action("describe_network_policy", policy_name="EXAMPLE")
        assert described.get_data() == [{"name": "property", "value": None}]

    def test_write_actions_keep_summaries_and_preserve_empty_values(self):
        row = {"status": "Statement executed successfully."}
        self.cursor.fetchone.return_value = row
        disabled = self.run_action("disable_user", username="EXAMPLE")
        assert disabled.get_data() == [row]
        assert disabled.get_summary() == {
            "new_login_status": "disabled",
            "existing_sessions": "not terminated",
        }
        updated = self.run_action(
            "update_network_policy", policy_name="EXAMPLE", allowed_ip_list=""
        )
        assert updated.get_status()
        assert "allowed_ip_list=()" in self.cursor.execute.call_args.args[0]
        assert "blocked_ip_list" not in self.cursor.execute.call_args.args[0]
        removed = self.run_action(
            "remove_grants", username="EXAMPLE", role_to_remove="READER"
        )
        assert removed.get_data() == [row]
        assert removed.get_message() == "Role READER was successfully removed from user"

    def test_sdk_action_returns_legacy_validation_message(self):
        params = {"username": "a b", "role_to_remove": "READER"}
        result = self.run_action("remove_grants", **params)
        assert not result.get_status()
        assert result.get_param() == params
        assert result.get_message().startswith("Invalid username.")
        assert "Traceback" not in result.get_message()
        self.cursor.execute.assert_not_called()

    def test_failed_vendor_requests_keep_original_parameters(self):
        self.cursor.execute.side_effect = RuntimeError("statement rejected")
        for action, params in (
            ("run_query", {"query": "select 1", "schema": "EXAMPLE"}),
            ("disable_user", {"username": "EXAMPLE", "role": "ADMIN"}),
            ("remove_grants", {"username": "EXAMPLE", "role_to_remove": "READER"}),
            ("show_network_policies", {"role": "READER"}),
            ("describe_network_policy", {"policy_name": "EXAMPLE"}),
            ("update_network_policy", {"policy_name": "EXAMPLE", "comment": "updated"}),
        ):
            with self.subTest(action=action):
                result = self.run_action(action, **params)
                assert not result.get_status()
                assert result.get_param() == params
                assert result.get_data() == []
                assert result.get_summary() == {}
                assert result.get_message().endswith(
                    "Error Message: statement rejected"
                )

    def test_failed_later_batch_keeps_earlier_rows_and_failed_status(self):
        self.cursor.description = [("X",)]
        for action, params, fetched, expected in (
            ("run_query", {"query": "select 1"}, ("first",), {"X": "first"}),
            ("show_network_policies", {}, {"name": "EXAMPLE"}, {"name": "EXAMPLE"}),
            (
                "describe_network_policy",
                {"policy_name": "EXAMPLE"},
                {"name": "COMMENT", "value": None},
                {"name": "COMMENT", "value": None},
            ),
        ):
            with self.subTest(action=action):
                self.cursor.fetchmany.side_effect = [
                    [fetched],
                    RuntimeError("fetch failed"),
                ]
                result = self.run_action(action, **params)
                assert not result.get_status()
                assert result.get_data() == [expected]
                assert result.get_summary() == {}
                assert result.get_message().endswith("Error Message: fetch failed")

    def test_custom_view_keeps_identical_inputs_and_empty_runs_separate(self):
        self.cursor.description = [("self",)]
        self.cursor.rowcount = 1
        self.cursor.fetchmany.side_effect = [[("<sample>",)], [], [("second",)], [], []]
        results = [self.run_action("run_query", query="select 1") for _ in range(3)]
        all_app_runs = [
            ({"total_objects": 1, "total_objects_successful": 1}, [result])
            for result in results
        ]
        context = {
            "QS": {},
            "container": 1,
            "app": 1,
            "no_connection": False,
            "google_maps_key": False,
        }
        document = display_query_results("run query", all_app_runs, context)
        assert context["prerender"]
        assert document.lstrip().startswith("<div")
        assert document.count('class="phantom-table dataTable"') == 2
        assert document.count("No data found") == 1
        assert document.count(">self</th>") == 2
        assert "&lt;sample&gt;" in document
