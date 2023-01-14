# File: snowflake_consts.py
#
# Copyright (c) 2022 Splunk Inc.
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
#

SNOWFLAKE_DATABASE = 'SNOWFLAKE'
SNOWFLAKE_ACCOUNT_ADMIN_ROLE = 'ACCOUNTADMIN'

SNOWFLAKE_VERSION_QUERY = 'SELECT current_version()'
TEST_CONNECTIVITY_MSG = 'Connecting to Snowflake endpoint'

EXECUTE_UPDATE_SQL_STATEMENT = ''
DISABLE_SNOWFLAKE_USER_SQL_STATEMENT = 'alter user {username} set disabled=true'
UPDATE_BLOCK_LIST_SQL_STATEMENT = ''
REMOVE_GRANTS_SQL_STATEMENT = ''
EDIT_TASK_AUTOMATION_SQL_STATEMENT = ''

SQL_QUERY_ERROR_MSG = 'SQL query failed'
DISABLE_USER_ERROR_MSG = 'Disable user failed'
SNOWFLAKE_ERROR_CODE_UNAVAILABLE = 'Unavailable'
SNOWFLAKE_ERROR_MSG_UNAVAILABLE = 'Unavailable. Please check the asset configuration and|or the action parameters.'

SNOWFLAKE_TOTAL_ROWS_JSON = 'total_rows'

# Security Insights SQL statements
SECURITY_INSIGHTS_SQL = {
    "Account Admin Grants": """
    select role, grantee_name, default_role from SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
    join SNOWFLAKE.ACCOUNT_USAGE.USERS on USERS.NAME = grants_to_users.grantee_name
    where role = 'ACCOUNTADMIN'
    and grants_to_users.deleted_on is null
    and USERS.DELETED_ON is null
    order by grantee_name;
    """,

    "Authentication Breakdown": """
    select first_authentication_factor || ' ' ||nvl(second_authentication_factor, '')
    as authentication_method, count(*)
    from account_usage.login_history
    where is_success = 'YES'
    group by authentication_method
    order by count(*) desc;
    """,

    "Disabled Users": """
    """,

    "Least Used Role Grants": """
    """,

    "Login Failures, by User, by Reason": """
    select user_name, error_message, count(*) num_of_failures
    from account_usage.login_history
    where is_success='NO'
    group by user_name, error_message
    order by num_of_failures desc;
    """,

    "Most Dangerous Person": """
    """,

    "Network Policy Change Management": """
    select user_name || ' made the following Network Policy change on ' || end_time || ' [' ||  query_text || ']' as Events
    from account_usage.query_history where execution_status = 'SUCCESS'
    and query_type in ('CREATE_NETWORK_POLICY', 'ALTER_NETWORK_POLICY', 'DROP_NETWORK_POLICY')
    or (query_text ilike '% set network_policy%'
    or query_text ilike '% unset network_policy%')
    and query_type != 'SELECT' and query_type != 'UNKNOWN'
    order by end_time desc;
    """,

    "Security Integration Change Management": """
    select user_name || ' made the following Security Integration change on ' || end_time || ' [' ||  query_text || ']' as Events
    from account_usage.query_history
    where execution_status = 'SUCCESS'
    and query_text ilike '%security integration%'
    and query_type != 'SELECT'
    order by end_time desc;
    """,

    "Stale User Accounts": """
    select name, datediff("day", last_success_login, current_timestamp()) || ' days ago' Last_Login
    from account_usage.users
    order by last_success_login;
    """,

    "User to Role Ratio": """
    """,

    "Users by Password Age": """
    select name, datediff('day', password_last_set_time, current_timestamp()) || ' days ago' as password_last_changed
    from account_usage.users
    where deleted_on is null and
    password_last_set_time is not null
    order by password_last_set_time;
    """
}
