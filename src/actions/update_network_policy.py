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

from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import UPDATE_NETWORK_POLICY_SQL, UPDATE_NETWORK_POLICY_SUCCESS_MSG
from ..connection import SnowflakeActionFailure, action_result, validated_identifier
from ..utils import build_network_policy_set_clause
from .statement import execute_statement


class UpdateNetworkPolicyParams(Params):
    policy_name: str = Param(
        description="Name of network policy to update",
        primary=True,
        cef_types=["snowflake policy name"],
        column_name="Policy Name",
    )
    role: str | None = Param(description="Role to use to execute action")
    allowed_ip_list: str | None = Param(
        description="Comma-separated list of IPs to replace the current allow list. Omit to leave unchanged or provide an empty list to clear it."
    )
    blocked_ip_list: str | None = Param(
        description="Comma-separated list of IPs to replace the current block list. Omit to leave unchanged or provide an empty list to clear it."
    )
    comment: str | None = Param(
        description="Replace the current network policy comment. Omit to leave unchanged or provide an empty value to clear it."
    )


def update_network_policy(params: UpdateNetworkPolicyParams, asset: Asset):
    with action_result(params) as result:
        policy_name = validated_identifier(params.policy_name, "policy_name")
        try:
            updates = build_network_policy_set_clause(
                allowed_ip_list=params.allowed_ip_list,
                blocked_ip_list=params.blocked_ip_list,
                comment=params.comment,
            )
        except ValueError as error:
            raise SnowflakeActionFailure(str(error)) from error
        execute_statement(
            result,
            asset,
            UPDATE_NETWORK_POLICY_SQL.format(
                policy_name=policy_name, set_clause=updates
            ),
            role=params.role,
        )
        result.set_status(
            True, UPDATE_NETWORK_POLICY_SUCCESS_MSG.format(policy_name=policy_name)
        )
    return result
