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

from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..connection import fetch_rows, normalize_row, open_cursor
from ..consts import DESCRIBE_NETWORK_POLICY_SQL, SNOWFLAKE_DATABASE
from ..connection import validated_identifier


class DescribeNetworkPolicyParams(Params):
    policy_name: str = Param(
        description="Name of policy to describe",
        primary=True,
        cef_types=["snowflake policy name"],
    )
    role: str | None = Param(description="Role to use to execute action")


class NetworkPolicyProperty(PermissiveActionOutput):
    name: str | None = None
    value: str | None = OutputField(
        cef_types=["ip"], example_values=["192.168.1.0/24,192.168.2.0/24"]
    )


def describe_network_policy(
    params: DescribeNetworkPolicyParams, asset: Asset
) -> list[NetworkPolicyProperty]:
    policy_name = validated_identifier(params.policy_name, "policy_name")
    with open_cursor(
        asset, dictionaries=True, database=SNOWFLAKE_DATABASE, role=params.role
    ) as cursor:
        cursor.execute(DESCRIBE_NETWORK_POLICY_SQL.format(policy_name=policy_name))
        return [
            NetworkPolicyProperty(**normalize_row(row)) for row in fetch_rows(cursor)
        ]
