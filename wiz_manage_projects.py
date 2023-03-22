# © 2022 Wiz, Inc.
# By using this software and associated documentation files (the “Software”) you hereby agree and understand that:
# 1. The use of the Software is free of charge and may only be used by Wiz customers for its internal purposes.
# 2. The Software should not be distributed to third parties.
# 3. The Software is not part of Wiz’s Services and is not subject to your company’s services agreement with Wiz.
# 4. THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL WIZ BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE USE OF THIS SOFTWARE
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Python 3.6+
# pip install requests, yaspin
import csv
import json
import os
import random
import re
import requests
import socket
import sys
import time
import traceback

from datetime import datetime
from operator import itemgetter
from typing import Any
from yaspin import yaspin

# Start a time to time total script execution time
start_time = datetime.now()

############### Start Script settings ###############

# Using a config file to store credential information
# We default to checking for a config file FIRST
# and then fall back to checking for environment vars
# Default will be skipped, update with real path to config file
wiz_config_file = "C:\WizDemo\WIZ-API\Recipe\SciprtModifyProjects\wiz_config.json"

# The relative path to the input file
# For example, on OSX for a desktop file it would be
# /Users/jdoe/Desktop/wiz-projects-to-create.csv
# Or, place the CSV in the same directory you're running the script from
projects_input_file = "C:\WizDemo\WIZ-API\Recipe\SciprtModifyProjects\wiz-projects-input.csv"
############### End Script settings ###############

############### Start Helpers ###############
class Timer:
    """
    A class to generate generic timer objects that we use to time function execution
    """

    def __init__(self, text: str):
        self.text = text
        self._start = datetime.now()

    def __str__(self) -> str:
        now = datetime.now()
        delta = now - self._start
        # split the time into minutes:seconds
        total_time = (
            f"{round(delta.total_seconds(),1)}"
            if delta.total_seconds() < 60
            # round rounds down by default, so we include a remainder in the calculation to force
            # a round up in the minutes calculation withouth having to include an additional library
            else f"{round((delta.total_seconds() // 60 + (delta.total_seconds() % 60 > 0)))}:{round((delta.total_seconds()% 60),1)}"
        )
        return f"{self.text} - Total elapsed time: {total_time}s"


def print_logo() -> None:
    """
    Print out the Wiz logo and script information

    Parameters:
        - none

    Returns:
        - none
    """
    print(
        f"""
                    __      _(_)____   ✦  ✦                                 
                    \ \ /\ / / |_  /     ✦                                  
                     \ V  V /| |/ /                                           
                      \_/\_/ |_/___|  © 2022 Wiz, Inc.     
+-------------------------------------------------------------------------+
  WIZ DATACENTER: {BLUE}{WIZ_DATACENTER}{END}
  API URL: {BLUE}{API_URL}{END}
  AUTH URL: {BLUE}{WIZ_AUTH_URL}{END} 
+-------------------------------------------------------------------------+
  SCRIPT NAME: {BLUE}{SCRIPT_NAME}{END} 
+-------------------------------------------------------------------------+
  {SCRIPT_DESCRIPTION}
+-------------------------------------------------------------------------+"""
    )


def _generic_exception_handler(function: Any) -> Any:
    """
    Private decorator function for error handling

    Parameters:
        - function: the function to pass in

    Returns:
        - _inner_function: the decorated function
    """

    def _inner_function(*args: Any, **kwargs: Any) -> Any:
        try:
            function_result = function(*args, **kwargs)
            return function_result
        except ValueError as v_err:
            print(traceback.format_exc(), f"{v_err}")
            sys.exit(1)
        except Exception as err:
            if (
                "502: Bad Gateway" not in str(err)
                and "503: Service Unavailable" not in str(err)
                and "504: Gateway Timeout" not in str(err)
            ):
                print(traceback.format_exc(), f"[ERROR]: {err}")
                return err

            else:
                print(traceback.format_exc(), "[ERROR] - Retry")

            sys.exit(1)

    return _inner_function


@_generic_exception_handler
def validate_config(
    client_id: str, client_secret: str, auth_url: str, api_url: str
) -> str:
    """
    Validate the the inputs from the config parser are valid
    And exit if any are not

    Parameters:
        - client_id: the wiz client id to check
        - client_secrete: the wiz client secret to check
        - auth_url: the wiz auth url to check
        - api_url: the wiz api url to check

    Returns:
        - wiz_dc: the datacenter extracted from the api url

    Returns:
        - wiz_dc: the wiz datacenter pulled from the config file or the local environment variables
    """
    # A current list of datacenters can be found at
    # https://docs.wiz.io/wiz-docs/docs/req-urls-ip-addr#datacenter-ip-addresses

    # Regex to match us1 - us28, and us28 - 36 (note the ranges we skip)
    US_DC_MATCHER = "(us+([1-9]|[1][0-9]|2[0-8]|3[2-6]))"
    # Regex to match eu1 - eu7
    EU_DC_MATCHER = "(eu+[1-7])"
    # Regex to match gov-us1 ONLY - can extend this later if we add more DCs
    GOV_DC_MATCHER = "(gov-us+[1])"
    # 32 char alphanumeric match for auth0 client ids
    AUTH0_CLIENT_ID_MATCHER = "([a-zA-Z0-9]{32})"
    # 52 or 53 char alphanumeric match for cognito client ids
    COGNITO_CLIENT_ID_MATCHER = "([a-zA-Z0-9]{52,53})"
    # 64 char alphanumeric match for secret
    SECRET_MATCHER = "([a-zA-Z0-9]{64})"

    WIZ_AUTH_ENDPOINTS = [
        "https://auth.app.wiz.io/oauth/token",  # Cognito
        "https://auth.demo.wiz.io/oauth/token",  # Cognito Demo
        "https://auth.wiz.io/oauth/token",  # Auth0 [legacy auth provider]
    ]

    # check to make sure the api url is valid
    if "https://api." not in api_url or not ".wiz.io/graphql" in api_url:
        sys.exit(
            f"[ERROR] {api_url} is not a valid Wiz API URL endpoint. Please check your config file and try again."
        )
    if auth_url not in WIZ_AUTH_ENDPOINTS:
        sys.exit(
            f"[ERROR] {auth_url} is not a valid Wiz Auth Endpoint. Please check your config file and try again. Exiting..."
        )
    # If we don't find a valid client ID, exit
    if not (
        re.fullmatch(AUTH0_CLIENT_ID_MATCHER, client_id)
        or re.fullmatch(COGNITO_CLIENT_ID_MATCHER, client_id)
    ):
        sys.exit(
            f"[ERROR] Did not find a valid Wiz Client ID. Please check your config file and try again. Exiting..."
        )

    # If we dont' find a valid secret, exit
    if not re.fullmatch(SECRET_MATCHER, client_secret):
        sys.exit(
            f"[ERROR] Did not find a valid Wiz Secret. Please check your config file and try again. Exiting..."
        )

    # Pull out only the Wiz DC to validate it is valid
    # Extracts <this-text> from  'api.<this-text>.'
    wiz_dc = api_url.partition("/api.")[2].partition(".")[0]

    # Check to make sure the datacenter is one of of our valid DCs
    if not (
        re.fullmatch(US_DC_MATCHER, wiz_dc)
        or re.fullmatch(EU_DC_MATCHER, wiz_dc)
        or re.fullmatch(GOV_DC_MATCHER, wiz_dc)
    ):
        sys.exit(
            f"[ERROR] {wiz_dc} is not a valid Wiz Datacenter. Please check and try again. Exiting..."
        )

    return wiz_dc


@_generic_exception_handler
def config_parser() -> tuple[str, str, str, str, str]:
    """
    Parse the system for a config file OR environment variables for the script to use
    The default behavior is to try a config file first, and then defer to environment variables

    Parameters:
        - none

    Returns:
        - WIZ_DATACENTER: the wiz datacenter pulled from the config file or the local environment variables
        - WIZ_CLIENT_ID: the wiz client id pulled from the config file or the local environment variables
        - WIZ_CLIENT_SECRET: the wiz client secret pulled from the config file or the local environment variables
        - WIZ_AUTH_URL: the wiz client id pulled from the config file or the local environment variables
        - API_URL: the wiz API URL
    """

    wiz_client_id, wiz_client_secret, wiz_auth_url, api_url = "", "", "", ""

    try:
        with open(f"{wiz_config_file}", mode="r") as config_file:
            config = json.load(config_file)

            # Extract the values from our dict and assign to vars
            api_url, wiz_auth_url, wiz_client_id, wiz_client_secret = itemgetter(
                "wiz_api_url", "wiz_auth_url", "wiz_client_id", "wiz_client_secret"
            )(config)

            # Validate the inputs and get the current Wiz DC back
            wiz_dc = validate_config(
                client_id=wiz_client_id,
                client_secret=wiz_client_secret,
                auth_url=wiz_auth_url,
                api_url=api_url,
            )

    except FileNotFoundError:
        pass

        try:
            wiz_client_id = str(os.getenv("wiz_client_id"))
            wiz_client_secret = str(os.getenv("wiz_client_secret"))
            wiz_auth_url = str(os.getenv("wiz_auth_url"))
            api_url = str(os.getenv("wiz_api_url"))

            # Validate the inputs and get the current Wiz DC back
            wiz_dc = validate_config(
                client_id=wiz_client_id,
                client_secret=wiz_client_secret,
                auth_url=wiz_auth_url,
                api_url=api_url,
            )

        except Exception:
            sys.exit(
                f"[ERROR] Unable to find one or more Wiz environment variables. Please check them and try again."
            )

    return (
        wiz_dc,
        wiz_client_id,
        wiz_client_secret,
        wiz_auth_url,
        api_url,
    )


@_generic_exception_handler
def set_socket_blocking() -> Any:
    """
    Sets blocking for http sockets so that no other internal libs
    can overwrite the defalt socket timeout

    Parameters:
        - none

    Returns:
        - none
    """
    setblocking_func = socket.socket.setblocking

    def wrapper(self: Any, flag: Any) -> Any:
        if flag:
            # prohibit timeout reset
            timeout = socket.getdefaulttimeout()
            if timeout:
                self.settimeout(timeout)
            else:
                setblocking_func(self, flag)
        else:
            setblocking_func(self, flag)

    wrapper.__doc__ = setblocking_func.__doc__
    wrapper.__name__ = setblocking_func.__name__
    return wrapper


############### End Helpers ###############

############### Start Script Config CONSTS ###############
# Colors
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
END = "\033[0m"
SPINNER_COLORS = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]
# Script info
SCRIPT_NAME = "Modify Wiz Projects Using Input File"
SCRIPT_DESCRIPTION = f"""{BLUE}DESCRIPTION:{END}
 - This script will modify Wiz projects using an input file
 - And prompt the user for relevant inputs"""
(
    WIZ_DATACENTER,
    WIZ_CLIENT_ID,
    WIZ_CLIENT_SECRET,
    WIZ_AUTH_URL,
    API_URL,
) = config_parser()
# Standard headers
HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded"}
HEADERS = {"Content-Type": "application/json"}
MAX_QUERY_RETRIES = 5
# define all the valid inputs and selections
RUN_MODE_OPTIONS = {
    "1": "DRY RUN",
    "2": "LIVE RUN",
}
PROJECT_MODIFY_OPTIONS = {
    "1": "Create new projects (do not modify existing)",
    "2": "Modify projects, (+) ADD subscriptions",
    "3": "Modify projects, (-) REMOVE subscriptions",
}
############### End Script Config CONSTS ###############

############### Start Queries and Vars ###############

create_projects_query = """
  mutation CreateProject($input: CreateProjectInput!) {
      createProject(input: $input) {
        project {
          id
        }
      }
    }
"""

get_cloud_account_details_query = """
  query CloudAccountsPage(
      $filterBy: CloudAccountFilters
      $first: Int
      $after: String
    ) {
      cloudAccounts(filterBy: $filterBy, first: $first, after: $after) {
        nodes {
          id
          name
          externalId
          cloudProvider
        }
      }
    }
"""

get_projects_query = """
query ProjectsTable($filterBy: ProjectFilters, $first: Int, $after: String, $orderBy: ProjectOrder) {
  projects(filterBy: $filterBy, first: $first, after: $after, orderBy: $orderBy) {
    nodes {
      id
      name
      slug
    }
    nodes {
      id
      name
      cloudAccountLinks {
        cloudAccount {
          id
          externalId
        }
        shared
        environment
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
    totalCount
  }
}
"""

update_project_query = """
mutation UpdateProject($input: UpdateProjectInput!) {
  updateProject(input: $input) {
    project {
      id
      name
      cloudAccountLinks {
        cloudAccount {
          id
        }
        environment
        shared
      }
    }
  }
}"""

create_projects_query_vars = {
    "input": {
        "name": "",
        "identifiers": [],
        "cloudOrganizationLinks": [],
        "cloudAccountLinks": [],
        "repositoryLinks": [],
        "description": "",
        "securityChampions": [],
        "projectOwners": [],
        "businessUnit": "",
        "riskProfile": {
            "businessImpact": "MBI",
            "hasExposedAPI": "UNKNOWN",
            "hasAuthentication": "UNKNOWN",
            "isCustomerFacing": "UNKNOWN",
            "isInternetFacing": "UNKNOWN",
            "isRegulated": "UNKNOWN",
            "sensitiveDataTypes": [],
            "storesData": "UNKNOWN",
            "regulatoryStandards": [],
        },
    }
}

get_cloud_account_details_query_vars = {
    "first": 20,
    "filterBy": {"search": [""], "connectorIssueId": None},
}

get_projects_query_vars = {
    "first": 500,
    "filterBy": {"search": ""},
    "orderBy": {"field": "SECURITY_SCORE", "direction": "ASC"},
}

update_project_query_vars = {
    "input": {"id": "", "override": {"name": "", "slug": "", "cloudAccountLinks": []}}
}
############### End Queries and Vars ###############

############### Start functions ###############
@_generic_exception_handler
def prompt_user_input() -> tuple[str, str]:
    """
    Prompts user for valid input and returns true if yes is selected
    or false if no is selected

    Parameters:
        - none

    Returns:
        - : dry_run and user_selection_bool
    """

    run_mode_selection, run_option = "default", "default"
    project_modify_selection, project_modify_option = "default", "default"
    # prompt the user for if they want to create a dry run
    while run_mode_selection not in RUN_MODE_OPTIONS.keys():
        run_mode_selection = str(
            input(
                f"""+ Enter the number of the run mode:
  [1] {BLUE}{RUN_MODE_OPTIONS.get("1")}{END} (view changes only)
  [2] {BLUE}{RUN_MODE_OPTIONS.get("2")}{END} (apply changes)
  selection: """
            )
        ).strip()
        if run_mode_selection in RUN_MODE_OPTIONS.keys():
            run_option = str(RUN_MODE_OPTIONS.get(run_mode_selection))
            break
        else:
            print("Invalid Input. Please try again.")

    while project_modify_selection not in PROJECT_MODIFY_OPTIONS.keys():
        project_modify_selection = str(
            input(
                f"""+ RUN MODE: {BLUE}{run_option}{END} | Please enter the number of the option:
  [1] {BLUE}{PROJECT_MODIFY_OPTIONS.get("1")}{END}
  [2] {BLUE}{PROJECT_MODIFY_OPTIONS.get("2")}{END}
  [3] {BLUE}{PROJECT_MODIFY_OPTIONS.get("3")}{END}
  selection: """
            )
        ).strip()
        if project_modify_selection in PROJECT_MODIFY_OPTIONS.keys():
            project_modify_option = str(
                PROJECT_MODIFY_OPTIONS.get(project_modify_selection)
            )
            print(
                f"+ RUN MODE: {BLUE}{run_option}{END} | SELECTION: {BLUE}{project_modify_option}{END}"
            )
            break
        else:
            print("Invalid Input. Please try again.")

    os.system("cls" if os.name == "nt" else "clear")

    print_logo()

    # sleep the screen for 1 second, to make output easier to read.
    time.sleep(1)

    print(
        f"""   RUN MODE: {BLUE}{run_option}{END} | SELECTION: {BLUE}{project_modify_option}{END} 
+-------------------------------------------------------------------------+
   INPUT FILE: {BLUE}{projects_input_file}{END}
+-------------------------------------------------------------------------+"""
    )

    return run_mode_selection, project_modify_selection


@_generic_exception_handler
def query_wiz_api(query: str, variables: dict) -> dict:
    """
    Query the WIZ API for the given query data schema
    Parameters:
        - query: the query or mutation we want to run
        - variables: the variables to be passed with the query or mutation
    Returns:
        - result: a json representation of the request object
    """

    # Init counters for retries, backoff
    retries = 0
    backoff = 0

    response = requests.post(
        url=API_URL, json={"variables": variables, "query": query}, headers=HEADERS
    )

    code = response.status_code

    # Handle retries, and exponential backoff logic
    while code != requests.codes.ok:
        # Increment backoff counter
        backoff += 1
        if retries >= MAX_QUERY_RETRIES:
            raise Exception(
                f"[ERROR] Exceeded the maximum number of retries [{response.status_code}] - {response.text}"
            )

        if code == requests.codes.unauthorized or code == requests.codes.forbidden:
            raise Exception(
                f"[ERROR] Authenticating to Wiz [{response.status_code}] - {response.text}"
            )
        if code == requests.codes.not_found:
            raise Exception(f"[ERROR] Unknown error [{response.status_code}]")

        if backoff != 0:
            print(f"\n└─ Backoff triggered, waiting {backoff}s and retrying.")

        time.sleep(backoff)

        response = requests.post(
            url=API_URL, json={"variables": variables, "query": query}, headers=HEADERS
        )
        code = response.status_code
        retries += 1

    # Catch edge case where we get a valid response but empty response body
    if not response:
        time.sleep(backoff)
        response = requests.post(
            url=API_URL, json={"variables": variables, "query": query}, headers=HEADERS
        )
        raise Exception(f"\n API returned no data or emtpy data set. Retrying.")

    response_json = response.json()

    if response_json.get("errors"):
        errors = response_json.get("errors")
        raise Exception(
            f'\n └─ MESSAGE: {errors["message"]}, \n └─ CODE: {errors["extensions"]["code"]}'
        )

    if response_json.get("code") == "DOWNSTREAM_SERVICE_ERROR":
        errors = response_json.get("errors")
        request_id = errors["message"].partition("request id: ")[2]

        raise Exception(
            f"[ERROR] - DOWNSTREAM_SERVICE_ERROR - request id: {request_id}"
        )

    return response_json


@_generic_exception_handler
def request_wiz_api_token(auth_url: str, client_id: str, client_secret: str) -> None:
    """
    Request a token to be used to authenticate against the wiz API

    Parameters:
        - client_id: the wiz client ID
        - client_secret: the wiz secret

    Returns:
        - TOKEN: A session token
    """
    audience = (
        "wiz-api" if "auth.app" in auth_url or "auth.gov" in auth_url else "beyond-api"
    )

    auth_payload = {
        "grant_type": "client_credentials",
        "audience": audience,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    # Initliaze a timer
    func_time = Timer("+ Requesting Wiz API token")

    with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):

        # Request token from the Wiz API
        response = requests.post(
            url=auth_url, headers=HEADERS_AUTH, data=auth_payload, timeout=None
        )

        if response.status_code != requests.codes.ok:
            raise Exception(
                f"Error authenticating to Wiz {response.status_code} - {response.text}"
            )

        response_json = response.json()

        response.close()

        TOKEN = response_json.get("access_token")

        if not TOKEN:
            raise Exception(
                f'Could not retrieve token from Wiz: {response_json.get("message")}'
            )

        HEADERS["Authorization"] = "Bearer " + TOKEN

    print(func_time, "\n└─ DONE: Received API token from Wiz")


@_generic_exception_handler
def update_project(
    project_id: str, project_name: str, slug: str, cloud_accounts: dict, mode: str
) -> None:
    """
    A wrapper around the query_wiz_api function
    That adds subscriptions to a project

    Parameters:
        - project_id: the UID of the project we want to add subscriptions to
        - cloud_accounts: the UIDs of the clound accounts/subscriptions we want to add to the project
        - mode: will wither be "DRY RUN" or "LIVE RUN" and allows user to control if this is dry run

    Returns:
        - none
    """
    print(f'+ {BLUE}{mode}{END} - Updating project "{GREEN}{project_name}{END}"')

    func_time = Timer("")
    # Initliaze a timer

    #     "input": {"id": "", "override": {"name": "", "slug": "", "cloudAccountLinks": []}}

    with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
        # Set the value of the current project to search by
        update_project_query_vars["input"]["id"] = project_id
        update_project_query_vars["input"]["override"][
            "cloudAccountLinks"
        ] = cloud_accounts
        update_project_query_vars["input"]["override"]["name"] = project_name
        update_project_query_vars["input"]["override"]["slug"] = slug
        # Query the wiz API
        result = query_wiz_api(
            query=update_project_query,
            variables=update_project_query_vars,
        )


@_generic_exception_handler
def create_project(project_name: str, cloud_accounts: list, mode: str) -> None:
    """
    A wrapper around the query_wiz_api function
    That creates a new wiz project

    Parameters:
        - project_name: the name of the project we want to create
        - cloud_accounts: the UIDs of the clound accounts/subscriptions we want to add to the project
        - mode: will wither be "DRY RUN" or "LIVE RUN" and allows user to control if this is dry run

    Returns:
        - none
    """
    # Initliaze a timer
    print(f'+ {BLUE}{mode}{END} - Creating project "{GREEN}{project_name}{END}"')
    func_time = Timer("")

    with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
        # Set the value of the current project to search by

        create_projects_query_vars["input"]["name"] = project_name
        create_projects_query_vars["input"]["cloudAccountLinks"] = cloud_accounts

        # Query the wiz API
        query_wiz_api(
            query=create_projects_query,
            variables=create_projects_query_vars,
        )

    print(func_time, f'\n└─ DONE: Created Project "{project_name}".')
    print(
        "└── Consider editing the newly created project and tweaking its settings."
        "\n└── e.g., description, risk profiile, regulatory standards, etc.",
    )


@_generic_exception_handler
def get_cloud_account_details(account_id: str, mode: str) -> list:
    """
    A wrapper around the query_wiz_api function
    That adds fetches details of a unique cloud account

    Parameters:
        - account_id: the account ID we want to get details for
        - mode: will wither be "DRY RUN" or "LIVE RUN" and allows user to control if this is dry run

    Returns:
        - (optional) cloud_accounts: a list of cloud accounts if they exist
    """
    # Initliaze a timer
    cloud_accounts = []
    print(
        f"+ {BLUE}{mode}{END} - Fetching Cloud Account Details for {GREEN}{account_id}{END}"
    )
    func_time = Timer("")

    with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
        # Set the value of the current project to search by
        get_cloud_account_details_query_vars["filterBy"]["search"] = account_id

        # Query the wiz API
        result = query_wiz_api(
            query=get_cloud_account_details_query,
            variables=get_cloud_account_details_query_vars,
        )

        cloud_accounts = result["data"]["cloudAccounts"]["nodes"]

    return cloud_accounts


@_generic_exception_handler
def get_wiz_project_data(project_name: str, mode: str) -> str:
    """
    A wrapper around the query_wiz_api function
    That gets info about a Wiz project

    Parameters:
        - project_name: the name of the project we want to get details for
        - mode: will wither be "DRY RUN" or "LIVE RUN" and allows user to control if this is dry run

    Returns:
        - project_data: information about the project
    """

    func_time = Timer("")

    with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
        # Set the value of the current project to search by
        get_projects_query_vars["filterBy"]["search"] = project_name

        # Query the wiz API
        result = query_wiz_api(
            query=get_projects_query, variables=get_projects_query_vars
        )

        project_data = result["data"]["projects"]["nodes"]

    return project_data


@_generic_exception_handler
def process_projects(project_input_file: list, mode: str, option: str) -> dict:
    """
    Processes the input file and creates and updates projects based on user selection

    Parameters:
        - project_input_file: a csv of the projects to add, where column 0 is the name
        and column 1 is the csv list of accounts to add
        otherwise it will not modify existing projects
        - mode: will wither be "DRY RUN" or "LIVE RUN" and allows user to control if this is dry run
        - option: the option the user has selected for either creating and updating projects
        or only creating new ones

    Returns:
        - skipped: a dict of accounts and projects we may have skipped
    """

    # Three cases we handle:
    # "1": "Create new projects (do not modify existing)"
    # "2": "Modify projects, (+) ADD subscriptions"
    # "3": "Modify projects, (-) REMOVE subscriptions"

    script_mode = str(RUN_MODE_OPTIONS.get(mode))

    # To track any accounts we may have skipped
    skipped = {"skipped": []}

    # Iterate through each project in the CSV input file
    for project in project_input_file:

        # first column cell is treated as the project name
        input_file_project_name = str(project[0])

        # second column cell is treated as the list of cloud accounts/subscriptions
        # separated by commas, for example "1111111, 2222222, 3333333"
        # We split this into a list of strings as the input is a single flat string
        input_file_cloud_accounts = project[1].split(",")

        if input_file_cloud_accounts:
            pass

        print(
            f"+-------------------------------------------------------------------------+"
            f"\n+ {BLUE}{script_mode}{END} - INPUT FILE PROJECT: {GREEN}{input_file_project_name}{END}"
            f"\n+-------------------------------------------------------------------------+"
        )

        # init a blank list for us to track all the accounts to to add to the project
        local_cloud_account_uids = []

        # "1": "Create new projects (do not modify existing)"
        if option == "1":
            skipped_accounts = []
            # Track the accounts we actually added from the input file
            valid_input_accounts = []
            print(
                f'+ {BLUE}{script_mode}{END} - Checking if "{GREEN}{input_file_project_name}{END}" exists in Wiz'
            )

            # Retrieve the project data based on the input file name
            wiz_project_data = get_wiz_project_data(
                project_name=input_file_project_name, mode=mode
            )

            # We did not find the project in Wiz, then we create it
            if not wiz_project_data:

                print(
                    f"└─ Project {GREEN}{input_file_project_name}{END} does not already exist in Wiz, creating it"
                )

                print(
                    f"+ {BLUE}{script_mode}{END} - Attempting to {BLUE}(+) ADD{END} the following CloudAccounts:"
                    f"\n└─ {GREEN}{input_file_cloud_accounts}{END} "
                )

                # Iterate through each of the accounts listed in the CSV
                # And retrieve the Wiz UID for the corresponding account/subscription
                for input_account in input_file_cloud_accounts:

                    # fetch Wiz UID of the subscription/cloud account
                    wiz_account_info = get_cloud_account_details(
                        account_id=input_account, mode=script_mode
                    )
                    # Check for edge case where we get a null value back for the account account data
                    if wiz_account_info:

                        print(f"└─ Found {GREEN}{input_account}{END} in Wiz")
                        # append the dict to the existing list with the current cloud account/subscription
                        wiz_account_uid = wiz_account_info[0]["id"]

                        # Update our linked cloud accounts list with the UID from the project query
                        local_cloud_account_uids.append(
                            {
                                "cloudAccount": wiz_account_uid,
                                "environment": "PRODUCTION",
                                "shared": False,
                            }
                        )
                        valid_input_accounts.append(input_account)
                    #
                    #  If the list has entries, then the project exists in Wiz
                    else:
                        # skipped_accounts += input_account
                        skipped_accounts.append(str(input_account))
                        print(
                            f"└─ CloudAccount {RED}{input_account}{END} was not found in your Wiz tenant",
                            f"\n+ {BLUE}{script_mode}{END} - Please enusre the CloudAccount exists in Wiz the name matches the input file",
                        )
                # If there are any skipped accounts in the list
                # Add them to our tracker
                if skipped_accounts:
                    skipped["skipped"].append(
                        {
                            "project": str(input_file_project_name),
                            "cloudAccounts": skipped_accounts,
                        }
                    )

                if valid_input_accounts:
                    # "1": "DRY RUN" only print what we would have done
                    if mode == "1":
                        print(
                            f"+ {BLUE}{script_mode}{END} - Script would create project {GREEN}{input_file_project_name}{END} with linked accounts: \n└─ {GREEN}{valid_input_accounts}{END}"
                        )

                    # "2": "LIVE RUN", query the API with the validated inputs
                    elif mode == "2":
                        create_project(
                            project_name=input_file_project_name,
                            cloud_accounts=local_cloud_account_uids,
                            mode=script_mode,
                        )
                else:
                    print(
                        f"+ {BLUE}{script_mode}{END} - Unknown state reached for creating projects!"
                    )
            # If the project exists, skip it since we're in option 1 (Create new projects (do not modify existing))
            else:
                skipped["skipped"].append(
                    {
                        "project": str(input_file_project_name),
                        "cloudAccounts": input_file_cloud_accounts,
                    }
                )

                print(
                    f'+ {BLUE}{script_mode}{END} - Project "{GREEN}{input_file_project_name}{END}" exists in Wiz'
                    f"\n└─ We will {RED}NOT modify{END} this project",
                )

        # Adding or removing projects is the same API call (update)
        # We handle most of the conditional logic for both in the same case
        # "2": "Modify projects, (+) ADD subscriptions"
        # "3": "Modify projects, (-) REMOVE subscriptions"
        if option == "2" or option == "3":
            print(
                f'+ {BLUE}{script_mode}{END} - Checking if project "{GREEN}{input_file_project_name}{END}" already exists in Wiz'
            )

            # Retrieve the project data based on the input file name
            wiz_project_data = get_wiz_project_data(
                project_name=input_file_project_name, mode=script_mode
            )

            # We did not find the project in Wiz, then we skip based on the current selected option
            if not wiz_project_data:

                skipped["skipped"].append(
                    {
                        "project": str(input_file_project_name),
                        "cloudAccounts": input_file_cloud_accounts,
                    }
                )

                print(
                    f"+ {BLUE}{script_mode}{END} - Project {GREEN}{input_file_project_name}{END} was {RED}not found{END} in Wiz"
                    f"\n└─ Please check your input file and Wiz to verify the project information"
                    f"\n+ {BLUE}{script_mode}{END} - Skipping and proceeding normally"
                )

            else:
                project_slug = wiz_project_data[0]["slug"]
                project_id = wiz_project_data[0]["id"]

                print(f"└─ Project {GREEN}{input_file_project_name}{END} found in Wiz")

                # if wiz_project_data[0]["cloudAccountLinks"] is not None:
                current_wiz_account_uids = wiz_project_data[0]["cloudAccountLinks"]

                # print("current acct uids:", current_wiz_account_uids)
                # Handle edge case where cloudAccount contains a null/none value
                # Rebuild the list via comprehension with condition
                current_wiz_account_uids = [
                    cloud_act
                    for cloud_act in current_wiz_account_uids
                    if cloud_act["cloudAccount"] is not None
                ]

                updated_wiz_account_uids = current_wiz_account_uids

                # Here we use zip to reformat the list of dicts "local_cloud_account_uids"
                # to pull out the id from the nested key and reassign it's value
                # BEFORE: [{'cloudAccount': {'id': '1234-abcde-12345-efghij', 'externalId': 'fffff'}, 'shared': False, 'environment': 'PRODUCTION', 'resourceGroups': None, 'resourceTags': None}]
                # AFTER: [{'cloudAccount': '1234-abcde-12345-efghij', 'shared': False, 'environment': 'PRODUCTION', 'resourceGroups': None, 'resourceTags': None}]

                for item_current, item_new in zip(
                    current_wiz_account_uids, updated_wiz_account_uids
                ):
                    item_new["cloudAccount"] = item_current["cloudAccount"]["id"]

                # "2": "Modify projects, (+) ADD subscriptions"
                if option == "2":
                    # Track any accounts we skipped
                    skipped_accounts = []
                    # Track the accounts we actually added from the input file
                    valid_input_accounts = []

                    print(
                        f"+ {BLUE}{script_mode}{END} - Attempting to {BLUE}(+) ADD{END} the following CloudAccounts:"
                        f"\n└─ {GREEN}{input_file_cloud_accounts}{END} "
                    )

                    # Iterate through the list of accounts from the input file CSV
                    for input_account in input_file_cloud_accounts:

                        # fetch Wiz UID of the subscription ID from the input
                        # To see if the account exists in Wiz
                        wiz_account_info = get_cloud_account_details(
                            account_id=input_account, mode=script_mode
                        )

                        if wiz_account_info:

                            wiz_account_uid = wiz_account_info[0]["id"]

                            # If the input project is not already in the projects list from the tenant
                            # from the tenant, then add the new project
                            if not any(
                                acct["cloudAccount"] == wiz_account_uid
                                for acct in updated_wiz_account_uids
                            ):
                                updated_wiz_account_uids.append(
                                    {
                                        "cloudAccount": wiz_account_uid,
                                        "environment": "PRODUCTION",
                                        "shared": False,
                                    }
                                )
                                valid_input_accounts.append(input_account)
                                print(
                                    f"└─ Found CloudAccount {GREEN}{input_account}{END} in Wiz. It will be {BLUE}(+)ADDED{END}"
                                )

                            # Otherwise check if the account is already there
                            # And skipp adding it
                            else:
                                if any(
                                    acct["cloudAccount"] == wiz_account_uid
                                    for acct in updated_wiz_account_uids
                                ):
                                    print(
                                        f"└─ Account {GREEN}{input_account}{END} is {RED}already associated{END} with this project and will not be added"
                                    )
                                    skipped_accounts.append(str(input_account))
                                    pass

                        else:
                            skipped_accounts.append(str(input_account))
                            print(
                                f"└─ CloudAccount {GREEN}{input_account}{END} was {RED}not found{END} in your Wiz tenant",
                                "\n└─── Please ensure the CloudAccount exists in Wiz and the name matches the input file.",
                            )
                            pass

                    # If there are any skipped accounts in the list
                    # Add them to our tracker
                    if skipped_accounts:
                        skipped["skipped"].append(
                            {
                                "project": str(input_file_project_name),
                                "cloudAccounts": skipped_accounts,
                            }
                        )
                    # Check if we even have any changes to make
                    if valid_input_accounts:

                        # "1": "DRY RUN" only print what we would have done
                        if mode == "1":
                            print(
                                f"+ {BLUE}{script_mode}{END} - Script would have updated linked CloudAccounts for project:"
                                f"\n└─ {GREEN}{valid_input_accounts}{END}"
                                f"\n+ Checking for other projects from the input file"
                            )

                        # "2": "LIVE RUN", query the API with the validated inputs
                        elif mode == "2":
                            update_project(
                                project_id=project_id,
                                slug=project_slug,
                                project_name=input_file_project_name,
                                cloud_accounts=updated_wiz_account_uids,
                                mode=script_mode,
                            )
                            print(
                                f'+ {BLUE}{script_mode}{END} - Successfully updated project "{GREEN}{input_file_project_name}{END}" with CloudAccounts:'
                                f"\n└─ {GREEN}{valid_input_accounts}{END}"
                                f"\n+ Checking for other projects from the input file"
                            )
                    else:
                        print(
                            f"+ {BLUE}{script_mode}{END} - No changes need to be made in Wiz"
                        )

                # "3": "Modify projects, (-) REMOVE subscriptions"
                if option == "3":
                    # Track any accounts we skipped
                    skipped_accounts = []
                    # Track the accounts we actually added from the input file
                    valid_input_accounts = []
                    # Edge case where a project has no CloudAccounts/subscriptions associated with it
                    if not updated_wiz_account_uids:
                        print(
                            f"+ {GREEN}{input_file_project_name}{END} {RED}does not{END} have any CloudAccounts associated"
                            f"\n└─ Nothing to remove"
                        )
                        skipped["skipped"].append(
                            {
                                "project": str(input_file_project_name),
                                "cloudAccounts": input_file_cloud_accounts,
                            }
                        )
                        pass

                    else:
                        print(
                            f"+ {BLUE}{script_mode}{END} - Attempting to {BLUE}(-) REMOVE {END} the following CloudAccounts:"
                            f"\n└─ {GREEN}{input_file_cloud_accounts}{END} "
                        )
                        for input_account in input_file_cloud_accounts:

                            # fetch Wiz UID of the subscription ID from the input
                            # To see if the account exists in Wiz
                            wiz_account_info = get_cloud_account_details(
                                account_id=input_account, mode=script_mode
                            )

                            # The subscription exists in Wiz
                            if wiz_account_info:

                                wiz_account_uid = wiz_account_info[0]["id"]

                                # Edge case - Check if the current cloud account
                                # Is in the Wiz project using a list comprehension with not any condition
                                if not any(
                                    acct["cloudAccount"] == wiz_account_uid
                                    for acct in updated_wiz_account_uids
                                ):
                                    # skipped_accounts += input_file_project_name
                                    skipped_accounts.append(str(input_account))
                                    print(
                                        f"└─ Account {GREEN}{input_account}{END} is {RED}not associated{END} with this project"
                                        "\n└─── Please enusre the CloudAccount exists in Wiz the name matches the input file."
                                    )

                                else:
                                    # for account_uid in updated_wiz_account_uids:
                                    # list comprehension update the list, removing the current
                                    # input file cloud account from the list of CloudAccounts
                                    updated_wiz_account_uids = [
                                        cloud_acct
                                        for cloud_acct in updated_wiz_account_uids
                                        if not (
                                            wiz_account_uid
                                            == cloud_acct.get("cloudAccount")
                                        )
                                    ]

                                    print(
                                        f"└─ Found CloudAccount {GREEN}{input_account}{END} in Wiz. It will be {BLUE}(-)REMOVED{END}"
                                    )
                                    valid_input_accounts.append(input_account)

                            else:
                                skipped_accounts.append(str(input_account))
                                print(
                                    f"└─ CloudAccount {GREEN}{input_account}{END} was {RED}not found{END} in your Wiz tenant",
                                    "\n└─── Please enusre the CloudAccount exists in Wiz the name matches the input file",
                                )

                        # If there are any skipped accounts in the list
                        # Add them to our tracker
                        if skipped_accounts:
                            skipped["skipped"].append(
                                {
                                    "project": str(input_file_project_name),
                                    "cloudAccounts": skipped_accounts,
                                }
                            )
                        if valid_input_accounts:
                            # "1": "DRY RUN" only print what we would have done
                            if mode == "1":
                                print(
                                    f"+ {BLUE}{script_mode}{END} - Updated linked accounts:"
                                )

                                if updated_wiz_account_uids:
                                    print(f"└─ {GREEN}{valid_input_accounts}{END}")

                                else:
                                    print(
                                        f"└─ The project will have no linked CloudAccounts as they were all removed"
                                    )

                            # "2": "LIVE RUN", query the API with the validated inputs
                            elif mode == "2":
                                update_project(
                                    project_id=project_id,
                                    slug=project_slug,
                                    project_name=input_file_project_name,
                                    cloud_accounts=updated_wiz_account_uids,
                                    mode=script_mode,
                                )
                                print(
                                    f'+ {BLUE}{script_mode}{END} - Successfully updated project "{GREEN}{input_file_project_name}{END}" with CloudAccounts:'
                                    f"\n└─ {GREEN}{valid_input_accounts}{END}"
                                )

                            print(
                                f"+ {BLUE}{script_mode}{END} - Checking for other projects from the input file"
                            )

    print(
        "+-------------------------------------------------------------------------+"
        f"\n+ {BLUE}{script_mode}{END} - FINISHED PROCESSING INPUT FILE"
        f"\n+-------------------------------------------------------------------------+"
    )
    return skipped


############### End functions ###############


############### Init main, call functions, helpers ###############
def main() -> None:
    print_logo()

    # Set default socket timeout to 20 seconds
    socket.setdefaulttimeout(20)

    # Set blocking to prevent overrides of socket timeout
    # docs: https://docs.python.org/3/library/socket.html#socket-timeouts
    socket.socket.setblocking = set_socket_blocking()

    func_time = Timer(f"+ Processing input file data.")

    with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
        try:
            with open(projects_input_file, newline="") as file_in:
                # Reading and ignoring the first line as it has the CSV headers...
                file_in.readline()
                reader = csv.reader(file_in, delimiter=",")
                projects = list(reader)

        except FileNotFoundError:
            sys.exit(
                f"\nThe input file {GREEN}{projects_input_file}{END} could not be found! \nPlease check if this file exists and try again."
            )

    print(
        func_time,
        f"\n└─ DONE: Processed {GREEN}{projects_input_file}{END}",
    )

    # Prompt the user for input, return bool based on input
    # prompt_user_input returns run_mode_selection, project_modify_selection
    script_mode, user_option = prompt_user_input()

    # Request the Wiz API token, token life is 1440 mins
    # request_wiz_api_token(client_id=client_id, client_secret=client_secret)
    request_wiz_api_token(
        auth_url=WIZ_AUTH_URL, client_id=WIZ_CLIENT_ID, client_secret=WIZ_CLIENT_SECRET
    )

    # Process the project data
    skipped_entries = process_projects(
        project_input_file=projects,
        mode=script_mode,
        option=user_option,
    )

    # Check if the skipped accounts list is empty
    # And print out if there are any

    """
        skipped_acts = {
        "skipped": [
            {"project": str(input_file_project_name), "cloudAccounts": skipped_accounts}
        ]
    }
    """

    # If we find any skipped entries
    if len(skipped_entries["skipped"]) != 0:
        print(
            f"+ {BLUE}{RUN_MODE_OPTIONS.get(script_mode)}{END} - During the processing of the input file we skipped the following:"
        )
        for project in skipped_entries["skipped"]:
            print(
                f'+ {BLUE}{RUN_MODE_OPTIONS.get(script_mode)}{END} - Input Project Name: {GREEN}{project["project"]}{END}'
                f'\n└─ CloudAccounts: {GREEN}{project["cloudAccounts"]}{END}'
            )

    end_time = datetime.now()

    total_elapsed_time = (
        f"{round((end_time - start_time).total_seconds(),1)}"
        if (end_time - start_time).total_seconds() < 60
        # round rounds down by default, so we include a remainder in the calculation to force
        # a round up in the minutes calculation withouth having to include an additional library
        else f"{round(((end_time - start_time).total_seconds() // 60 + ((end_time - start_time).total_seconds()% 60 > 0)))}:{round(((end_time - start_time).total_seconds()% 60),1)}"
    )

    print(
        f"+-------------------------------------------------------------------------+"
        f"\n+ {BLUE}{RUN_MODE_OPTIONS.get(script_mode)}{END} - Script Finished\n└─ Total script elapsed time: {total_elapsed_time}s"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n+ Ctrl+C interrupt received. Exiting.")
        pass
