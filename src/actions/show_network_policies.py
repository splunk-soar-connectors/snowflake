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

from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..connection import action_result, fetch_rows, normalize_row, open_cursor
from ..consts import SHOW_NETWORK_POLICIES_SQL, SNOWFLAKE_DATABASE


class ShowNetworkPoliciesParams(Params):
    role: str | None = Param(description="Role to use to execute action")


class NetworkPolicy(ActionOutput):
    name: str | None = None
    comment: str | None = None
    created_on: str | None = None
    entries_in_allowed_ip_list: int | None = None
    entries_in_blocked_ip_list: int | None = None


class NetworkPolicySummary(ActionOutput):
    total_policies: int


def show_network_policies(params: ShowNetworkPoliciesParams, asset: Asset):
    with action_result(params) as result:
        with open_cursor(
            asset, dictionaries=True, database=SNOWFLAKE_DATABASE, role=params.role
        ) as cursor:
            cursor.execute(SHOW_NETWORK_POLICIES_SQL)
            for row in fetch_rows(cursor):
                result.add_data(normalize_row(row))
        result.set_summary(
            NetworkPolicySummary(total_policies=len(result.get_data())).model_dump()
        )
    return result
