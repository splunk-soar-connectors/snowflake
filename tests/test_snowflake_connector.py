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
from soar_sdk.exceptions import ActionFailure

from src.actions.connectivity import test_connectivity as check_connectivity
from src.actions.describe_network_policy import (
    DescribeNetworkPolicyParams,
    describe_network_policy,
)
from src.actions.disable_user import DisableUserParams, disable_user
from src.actions.remove_grants import RemoveGrantsParams, remove_grants
from src.actions.run_query import RunQueryParams, run_query, unique_column_names
from src.actions.show_network_policies import (
    ShowNetworkPoliciesParams,
    show_network_policies,
)
from src.actions.update_network_policy import (
    UpdateNetworkPolicyParams,
    update_network_policy,
)
from src.app import app, display_query_results
from src.asset import Asset
import pytest


class SnowflakeConnectorTest(unittest.TestCase):
    def setUp(self):
        connect = self.enterContext(patch("snowflake.connector.connect"))
        self.connection = connect.return_value
        self.cursor = self.connection.cursor.return_value
        self.asset = Asset(account="example", username="example", password="fixture")
        self.soar = MagicMock(spec=SOARClient)

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
        self.cursor.description = [("NAME",), ("NAME",)]
        self.cursor.fetchmany.side_effect = [
            [("first", b"second")],
            [("third", "fourth")],
            [],
        ]
        self.cursor.rowcount = 2
        rows = run_query(
            RunQueryParams(query="select 1", schema="example"), self.soar, self.asset
        )
        assert [row.model_dump() for row in rows] == [
            {"NAME": "first", "NAME__duplicate_1": "second"},
            {"NAME": "third", "NAME__duplicate_1": "fourth"},
        ]
        assert self.soar.set_summary.call_args.args[0].model_dump() == {"total_rows": 2}
        self.cursor.close.assert_called_once()
        self.connection.close.assert_called_once()

    def test_query_with_no_result_columns_preserves_successful_empty_output(self):
        self.cursor.description = None
        self.cursor.rowcount = -1
        assert run_query(RunQueryParams(query="select 1"), self.soar, self.asset) == []
        assert self.soar.set_summary.call_args.args[0].model_dump() == {"total_rows": 0}
        self.cursor.fetchmany.assert_not_called()

    def test_connection_and_failed_query_close_resources(self):
        check_connectivity(self.soar, self.asset)
        self.soar.set_message.assert_called_once_with("Test connectivity passed")
        self.cursor.execute.side_effect = RuntimeError("test failure")
        with pytest.raises(
            ActionFailure, match="SQL query failed: Error Message: test failure"
        ):
            run_query(RunQueryParams(query="select 1"), self.soar, self.asset)
        assert self.cursor.close.call_count == 2
        assert self.connection.close.call_count == 2

    def test_show_and_describe_keep_policy_fields(self):
        self.cursor.fetchmany.side_effect = [
            [{"name": "example", "vendor_field": 1}],
            [],
            [{"name": "property", "value": None}],
            [],
        ]
        show = show_network_policies(ShowNetworkPoliciesParams(), self.soar, self.asset)
        assert show[0].model_dump() == {"name": "example", "vendor_field": 1}
        assert self.soar.set_summary.call_args.args[0].model_dump() == {
            "total_policies": 1
        }
        described = describe_network_policy(
            DescribeNetworkPolicyParams(policy_name="EXAMPLE"), self.asset
        )
        assert described[0].model_dump() == {"name": "property", "value": None}

    def test_write_actions_keep_summaries_preserve_empty_values_and_validate(self):
        self.cursor.fetchone.return_value = {
            "status": "Statement executed successfully."
        }
        disabled = disable_user(
            DisableUserParams(username="EXAMPLE"), self.soar, self.asset
        )
        assert disabled[0].model_dump() == {
            "status": "Statement executed successfully."
        }
        assert self.soar.set_summary.call_args.args[0].model_dump() == {
            "new_login_status": "disabled",
            "existing_sessions": "not terminated",
        }
        update_network_policy(
            UpdateNetworkPolicyParams(policy_name="EXAMPLE", allowed_ip_list=""),
            self.soar,
            self.asset,
        )
        assert "allowed_ip_list=()" in self.cursor.execute.call_args.args[0]
        assert "blocked_ip_list" not in self.cursor.execute.call_args.args[0]
        remove_grants(
            RemoveGrantsParams(username="EXAMPLE", role_to_remove="READER"),
            self.soar,
            self.asset,
        )
        called = self.cursor.execute.call_count
        with pytest.raises(ActionFailure, match="Invalid username"):
            remove_grants(
                RemoveGrantsParams(username="a b", role_to_remove="READER"),
                self.soar,
                self.asset,
            )
        assert self.cursor.execute.call_count == called

    def test_sdk_action_returns_legacy_validation_message(self):
        handler = app.get_actions()["remove_grants"]
        action_params = RemoveGrantsParams(username="a b", role_to_remove="READER")
        with (
            patch.object(
                app,
                "_build_magic_args",
                return_value={"soar": self.soar, "asset": self.asset},
            ),
            patch.object(app.actions_manager, "add_result") as add_result,
        ):
            handler(action_params, soar=self.soar)
        result = add_result.call_args.args[0]
        assert result.get_message().startswith("Invalid username.")
        assert "Traceback" not in result.get_message()
        self.cursor.execute.assert_not_called()

    def test_custom_view_formats_each_result_group(self):
        self.cursor.description = [("B",), ("A",)]
        self.cursor.fetchmany.side_effect = [[("b", "a")], []]
        self.cursor.rowcount = 1
        rows = run_query(RunQueryParams(query="select 1"), self.soar, self.asset)
        document = display_query_results.__wrapped__(
            rows + rows,
            params=[{"query": "first"}, {"query": "second"}],
            summary=[{"total_rows": 1}, {"total_rows": 1}],
        )
        assert len(document["results"]) == 2
        assert document["results"][0] == {
            "headers": ["A", "B"],
            "data": [[{"value": "a"}, {"value": "b"}]],
        }
