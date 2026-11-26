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

from itertools import groupby

from soar_sdk.action_results import PermissiveActionOutput
from soar_sdk.app import App

from .actions.connectivity import test_connectivity
from .actions.describe_network_policy import describe_network_policy
from .actions.disable_user import DisableUserSummary, disable_user
from .actions.remove_grants import remove_grants
from .actions.run_query import QuerySummary, run_query
from .actions.show_network_policies import NetworkPolicySummary, show_network_policies
from .actions.update_network_policy import update_network_policy
from .asset import Asset


app = App(
    name="Snowflake",
    app_type="siem",
    logo="logo_snowflake.svg",
    logo_dark="logo_snowflake_dark.svg",
    product_vendor="Snowflake",
    product_name="Snowflake",
    publisher="Splunk",
    appid="9dc1ac34-cac9-41fb-af81-e71ffe256f49",
    python_version="3.13",
    fips_compliant=False,
    asset_cls=Asset,
)


@app.view_handler(template="query_results.html")
def display_query_results(
    outputs: list[PermissiveActionOutput], *, params: list[dict], summary: list[dict]
) -> dict:
    tables = []
    for _, items in groupby(
        zip(outputs, params, summary, strict=True), key=lambda item: (item[1], item[2])
    ):
        rows = [item[0].model_dump(mode="json") for item in items]
        headers = sorted({column for row in rows for column in row})
        tables.append(
            {
                "headers": headers,
                "data": [
                    [{"value": row.get(column)} for column in headers] for row in rows
                ],
            }
        )
    return {"results": tables or [{"headers": [], "data": []}]}


app.test_connectivity()(test_connectivity)

app.action(
    description="Perform a SQL query",
    action_type="investigate",
    read_only=False,
    view_handler=display_query_results,
    summary_type=QuerySummary,
)(run_query)

app.action(
    description="Prevent a Snowflake user from starting new sessions. Existing sessions are not terminated",
    action_type="investigate",
    read_only=False,
    render_as="table",
    summary_type=DisableUserSummary,
)(disable_user)

app.action(
    description="List available network policies",
    action_type="investigate",
    read_only=True,
    view_handler=display_query_results,
    summary_type=NetworkPolicySummary,
)(show_network_policies)

app.action(
    description="List the details of a network policy",
    action_type="investigate",
    read_only=True,
    view_handler=display_query_results,
)(describe_network_policy)

app.action(
    description="Update an existing network policy",
    action_type="investigate",
    read_only=False,
    render_as="table",
)(update_network_policy)

app.action(
    description="Remove a specified granted role from a Snowflake user",
    action_type="investigate",
    read_only=False,
    render_as="table",
)(remove_grants)


if __name__ == "__main__":
    app.cli()
