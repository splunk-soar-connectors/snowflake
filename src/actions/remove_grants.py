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
from ..consts import REMOVE_GRANTS_SQL, REMOVE_GRANTS_SUCCESS_MSG
from ..connection import action_result, validated_identifier
from .statement import execute_statement


class RemoveGrantsParams(Params):
    username: str = Param(
        description="Username", cef_types=["user name"], column_name="Username"
    )
    role_to_remove: str = Param(
        description="Role to remove from user", column_name="Role to Remove"
    )
    role: str | None = Param(description="Role to use to execute action")


def remove_grants(params: RemoveGrantsParams, asset: Asset):
    with action_result(params) as result:
        username = validated_identifier(params.username, "username")
        role_to_remove = validated_identifier(params.role_to_remove, "role_to_remove")
        execute_statement(
            result,
            asset,
            REMOVE_GRANTS_SQL.format(username=username, role_to_remove=role_to_remove),
            role=params.role,
        )
        result.set_status(True, REMOVE_GRANTS_SUCCESS_MSG.format(role=role_to_remove))
    return result
