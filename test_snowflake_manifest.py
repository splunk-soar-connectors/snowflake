# File: test_snowflake_manifest.py
#
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

import json
import unittest
from pathlib import Path


class SnowflakeManifestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(Path("snowflake.json").read_text())

    def test_disable_user_documents_session_scope(self):
        action = next(action for action in self.manifest["actions"] if action["identifier"] == "disable_user")

        self.assertIn("Existing sessions are not terminated", action["description"])
        output_paths = {output["data_path"] for output in action["output"]}
        self.assertIn("action_result.summary.new_login_status", output_paths)
        self.assertIn("action_result.summary.existing_sessions", output_paths)

    def test_update_network_policy_documents_omitted_fields(self):
        action = next(action for action in self.manifest["actions"] if action["identifier"] == "update_network_policy")

        for parameter_name in ("allowed_ip_list", "blocked_ip_list", "comment"):
            with self.subTest(parameter_name=parameter_name):
                self.assertIn("Omit to leave unchanged", action["parameters"][parameter_name]["description"])


if __name__ == "__main__":
    unittest.main()
