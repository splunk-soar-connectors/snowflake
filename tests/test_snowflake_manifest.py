# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import unittest
from src.app import app
from src.asset import Asset


class SnowflakeManifestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            action.identifier: action.model_dump()
            for action in app.actions_manager.get_actions_meta_list()
        }

    def test_disable_user_documents_session_scope(self):
        action = self.actions["disable_user"]

        assert "Existing sessions are not terminated" in action["description"]
        output_paths = {output["data_path"] for output in action["output"]}
        assert "action_result.summary.new_login_status" in output_paths
        assert "action_result.summary.existing_sessions" in output_paths

    def test_preserves_sensitive_password_and_read_only_actions(self):
        assert Asset.to_json_schema()["password"]["data_type"] == "password"
        assert {
            name for name, action in self.actions.items() if action["read_only"]
        } == {"test_connectivity", "show_network_policies", "describe_network_policy"}

    def test_preserves_query_data_summary_and_custom_view_registration(self):
        query = self.actions["run_query"]
        paths = {field["data_path"] for field in query["output"]}
        assert "schema" in query["parameters"]
        assert "action_result.parameter.schema" in paths
        assert "action_result.data" in paths
        assert "action_result.summary.total_rows" in paths
        for name, title in (
            ("run_query", "Execute Query"),
            ("show_network_policies", "Show Network Policies"),
            ("describe_network_policy", "Describe Network Policy"),
        ):
            render = self.actions[name]["render"]
            assert render["view"].endswith("views.display_query_results")
            assert {
                key: render[key] for key in ("type", "width", "height", "title")
            } == {
                "type": "custom",
                "width": 10,
                "height": 5,
                "title": title,
            }

    def test_update_network_policy_documents_omitted_fields(self):
        action = self.actions["update_network_policy"]

        for parameter_name in ("allowed_ip_list", "blocked_ip_list", "comment"):
            with self.subTest(parameter_name=parameter_name):
                assert (
                    "Omit to leave unchanged"
                    in action["parameters"][parameter_name]["description"]
                )


if __name__ == "__main__":
    unittest.main()
