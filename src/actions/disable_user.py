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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..consts import (
    DISABLE_SNOWFLAKE_USER_SQL,
    DISABLE_USER_ERROR_MSG,
    DISABLE_USER_SUCCESS_MSG,
)
from ..connection import validated_identifier
from .statement import StatementResult, execute_statement


class DisableUserParams(Params):
    username: str = Param(
        description="Snowflake user name",
        primary=True,
        cef_types=["user name"],
        column_name="Username",
    )
    role: str | None = Param(description="Role to use to execute action")


class DisableUserSummary(ActionOutput):
    new_login_status: str
    existing_sessions: str


def disable_user(
    params: DisableUserParams, soar: SOARClient, asset: Asset
) -> list[StatementResult]:
    username = validated_identifier(params.username, "username")
    result = execute_statement(
        asset,
        DISABLE_SNOWFLAKE_USER_SQL.format(username=username),
        role=params.role,
        error_prefix=DISABLE_USER_ERROR_MSG,
    )
    soar.set_summary(
        DisableUserSummary(
            new_login_status="disabled", existing_sessions="not terminated"
        )
    )
    soar.set_message(DISABLE_USER_SUCCESS_MSG.format(username=username))
    return result
