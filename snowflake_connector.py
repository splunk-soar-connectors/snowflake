# File: snowflake_connector.py
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

import datetime
import json

# Phantom App imports
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

import snowflake.connector
from snowflake_consts import *


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SnowflakeConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SnowflakeConnector, self).__init__()

        self._state = None

        self._account = None
        self._username = None
        self._password = None

    def _get_error_message_from_exception(self, e):
        error_code = SNOWFLAKE_ERROR_CODE_UNAVAILABLE
        error_msg = SNOWFLAKE_ERROR_MSG_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception:
            pass

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def convert_value(self, value):
        if isinstance(value, (bytearray, bytes)):
            return value.decode('utf-8')
        elif isinstance(value, (datetime.datetime, datetime.timedelta, datetime.date)):
            return str(value)
        else:
            return value

    def _cleanup_row_values(self, row):
        return {k: self.convert_value(v) for k, v in row.items()}

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(TEST_CONNECTIVITY_MSG)

        connection = self._handle_create_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(SNOWFLAKE_VERSION_QUERY)
            one_row = cursor.fetchone()
            self.debug_print('Version is: {}'.format(one_row[0]))
            ret_val = True
        except Exception:
            action_result.set_status(phantom.APP_ERROR, 'Error connecting to Snowflake')
            ret_val = False
        finally:
            cursor.close()
            connection.close()

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_execute_query(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param['query']
        role = param.get('role')
        warehouse = param.get('warehouse')
        database = param.get('database')
        schema = param.get('schema')

        connection = self._handle_create_connection(role, warehouse, database, schema)
        cursor = connection.cursor(snowflake.connector.DictCursor)

        try:
            cursor.execute(query)
            returned_data = cursor.fetchmany(100)
            # self.debug_print(cursor.rowcount())
            for row in returned_data:
                action_result.add_data(self._cleanup_row_values(row))
            self.debug_print("returned_data: {}".format(returned_data))

            while len(returned_data) > 0:
                returned_data = cursor.fetchmany(100)
                for row in returned_data:
                    action_result.add_data(self._cleanup_row_values(row))

        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.save_progress("Error: {}".format(error_msg))
            return action_result.set_status(phantom.APP_ERROR, '{0}: {1}'.format(SQL_QUERY_ERROR_MSG, error_msg))

        finally:
            cursor.close()
        summary = action_result.update_summary({})

        if cursor.rowcount > 0:
            summary[SNOWFLAKE_TOTAL_ROWS_JSON] = cursor.rowcount
        else:
            summary[SNOWFLAKE_TOTAL_ROWS_JSON] = 0

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_execute_update(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # action_result = self.add_action_result(ActionResult(dict(param)))

    def _handle_disable_user(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        database = SNOWFLAKE_DATABASE
        role = SNOWFLAKE_ACCOUNT_ADMIN_ROLE

        username = param['username']

        connection = self._handle_create_connection(role=role, database=database)
        cursor = connection.cursor()

        try:
            cursor.execute(DISABLE_SNOWFLAKE_USER_SQL_STATEMENT.format(username=username))
            returned_data = cursor.fetchone()
            action_result.add_data(returned_data[0])
            # self.debug_print("returned_data: {}".format(returned_data))

        except Exception as e:
            self.debug_print("Error: {}".format(e))
            action_result.set_status(phantom.APP_ERROR, 'Disable user failed: {}'.format(e))
            return action_result.get_status()
        finally:
            cursor.close()
        summary = action_result.update_summary({})
        summary['message'] = action_result.get_data()[0]

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_block_list(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # action_result = self.add_action_result(ActionResult(dict(param)))

    def _handle_remove_grants(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # action_result = self.add_action_result(ActionResult(dict(param)))

    def _handle_edit_task_automation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # action_result = self.add_action_result(ActionResult(dict(param)))

    def _handle_security_insights(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        query = SECURITY_INSIGHTS_SQL[param['insight']]
        self.debug_print('Insight: {}, Query: {}'.format(param['insight'], query))

        # action_result = self._run_query(query, param, action_result)
        # return action_result

        database = 'SNOWFLAKE'
        role = 'ACCOUNTADMIN'
        warehouse = 'warehouse1'

        connection = self._handle_create_connection(database=database, role=role, warehouse=warehouse)

        cursor = connection.cursor(snowflake.connector.DictCursor)
        try:
            cursor.execute(query)
            # data = cursor.fetchall()
            for row in cursor:
                self.debug_print(row)
                action_result.add_data(row)

        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.save_progress("Error: {}".format(error_msg))
            return action_result.set_status(phantom.APP_ERROR, '{0}: {1}'.format(SQL_QUERY_ERROR_MSG, error_msg))

        finally:
            connection.close()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_query(self, sql, param, action_result):
        ret_val = False

        warehouse = param.get('warehouse')
        database = param.get('database')
        schema = param.get('schema')

        connection = self._handle_create_connection(warehouse=warehouse, database=database, schema=schema)
        cursor = connection.cursor()
        try:
            cursor.execute(sql)
            one_row = cursor.fetchone()
            ret_val = True
        except Exception:
            action_result.set_status(phantom.APP_ERROR, 'SQL query failed!')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(one_row[0])

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = len(one_row[0])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_connection(self, role=None, warehouse=None, database=None, schema=None):
        ctx = snowflake.connector.connect(
            user=self._username,
            password=self._password,
            account=self._account,
            role=role,
            warehouse=warehouse,
            database=database,
            schema=schema
        )
        return ctx

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        if action_id == 'execute_query':
            ret_val = self._handle_execute_query(param)

        if action_id == 'execute_update':
            ret_val = self._handle_execute_update(param)

        if action_id == 'disable_user':
            ret_val = self._handle_disable_user(param)

        if action_id == 'update_block_list':
            ret_val = self._handle_update_block_list(param)

        if action_id == 'remove_grants':
            ret_val = self._handle_remove_grants(param)

        if action_id == 'edit_task_automation':
            ret_val = self._handle_edit_task_automation(param)

        if action_id == 'security_insights':
            ret_val = self._handle_security_insights(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._account = config['account']
        self._username = config['username']
        self._password = config['password']

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    import pudb
    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = SnowflakeConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SnowflakeConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
