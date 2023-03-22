# Python 3.6+
# pip(3) install requests
import requests
import ipaddress

# Get the CIDR subnet from the user
cidr_subnet = input("Enter a CIDR subnet (e.g. 199.120.56.48/28): ")

# Convert the CIDR subnet to an IPNetwork object
subnet = ipaddress.ip_network(cidr_subnet, strict=False)

# Get the first and last IP addresses in the subnet
first_ip = subnet.network_address + 1
last_ip = subnet.broadcast_address - 1


# Standard headers
HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded"}
HEADERS = {"Content-Type": "application/json"}

client_id = "wgxq75hrlndpbktx3eupevf2x2howniyuzyvxbmyofppqgz7qbgxg"
client_secret = "7KQGM4NmLWj2fmwCpRvCO11Cy7AWTuxPMOVKMnASmlrz2U1nsh3YqIt3BIKFDxWo"

# Uncomment the following section to define the proxies in your environment,
#   if necessary:
# http_proxy  = "http://"+user+":"+passw+"@x.x.x.x:abcd"
# https_proxy = "https://"+user+":"+passw+"@y.y.y.y:abcd"
# proxyDict = {
#     "http"  : http_proxy,
#     "https" : https_proxy
# }

# The GraphQL query that defines which data you wish to fetch.
query = ("""
    mutation UpdateCloudConfigurationRule($ruleId: ID!, $patch: UpdateCloudConfigurationRulePatch!) {
      updateCloudConfigurationRule(input: {id: $ruleId, patch: $patch}) {
        rule {
          id
          targetNativeTypes
          opaPolicy
          functionAsControl
          name
          description
          severity
          remediationInstructions
          enabled
          control {
            id
          }
          iacMatchers {
            id
            type
            regoCode
          }
          securitySubCategories {
            id
            title
            description
            category {
              id
              name
              description
              framework {
                id
                name
                enabled
              }
            }
          }
          scopeAccounts {
            id
            name
            cloudProvider
          }
        }
      }
    }
""")

# The variables sent along with the above query
allowedStartIpAddress = {"199.120.56.25", "104.9.128.191", "199.120.56.49", ""+ str(first_ip) +""}
allowedEndIpAddress = {"199.120.56.90", "104.9.128.191", "199.120.56.62",""+ str(last_ip) +""}

# The variables sent along with the above query
variables = {
  "ruleId": "a79267b0-2b98-4ef9-b5ca-0a49915e25d2",
  "patch": {
    "targetNativeTypes": [
      "Microsoft.Sql/servers"
    ],
    "opaPolicy": "#\tUse the Rego code below to programmatically define a Cloud Configuration Rule\n#\tbased on the raw json of a resource. By default, every resource with the selected\n#\tNative Type will be assessed and will have either 'fail' or 'pass' result.\n# \n#\tYou must populate the 'result' variable in either of the following string:\n#\t1. \"pass\" - The rule resource assessment will be set as \"pass\".\n#\t\t\t\tWill not result in a Configuration Finding.\n#\t2. \"fail\" - The rule resource assessment will be set as \"failed\".\n#\t\t\t\tWill result in a Configuration Finding associated to the resource.\n#\t3. \"skip\" - The resource will not be assessed and will not be counted in compliance reporting.\n#\n#\tTo control the Expected Configuration and Current Configuration of a failed rule, declare\n#\tand populate 'currentConfiguration' and 'expectedConfiguration' variables with strings.\n#\n#\tTo use built-in future Rego functions, such as 'in', 'contains', 'every' and 'if' - add\n#\t'import future.keywords' to the code.\n\npackage wiz\nimport future.keywords.in\n\ndefault result = \"pass\"\n\n# Define the firewall rule for allowed IP range\nallowedStartIpAddress = {" + ", ".join(allowedStartIpAddress) + "}\nallowedEndIpAddress = {" + ", ".join(allowedEndIpAddress) + "}\n\n\n# Check if the incoming traffic is from the allowed IP address range\ndisallowedRange[rule]\n{\t\n\trule := input.FirewallRules[i].name\n    input.FirewallRules[i].type == \"Microsoft.Sql/servers/firewallRules\"\n    input.FirewallRules[i].name != \"AllowAllWindowsAzureIps\"\n    not input.FirewallRules[i].properties.startIpAddress in allowedStartIpAddress\n}{\n\trule := input.FirewallRules[i].name\n    input.FirewallRules[i].type == \"Microsoft.Sql/servers/firewallRules\"\n    input.FirewallRules[i].name != \"AllowAllWindowsAzureIps\"\n\tnot input.FirewallRules[i].properties.endIpAddress in allowedEndIpAddress\n}\n\nresult = \"fail\" {\n\tcount(disallowedRange) > 0\n}\n\ncurrentConfiguration := sprintf(\"SQL server firewall rules with disallowed IP range: %s\", [concat(\", \", disallowedRange)])\nexpectedConfiguration := \"SQL server firewall rules should be with allowed IP range\"",
    "scopeAccountIds": [],
    "functionAsControl": False,
    "name": "Azure SQL Server public access from IP's outside the defined range ",
    "description": "this control checks for any Azure SQL Server that is accessible from outside the defined range in the CCR \n",
    "severity": "MEDIUM",
    "securitySubCategories": [
      "ab1d2c15-3e41-491d-bf3f-5c77cf95e0bb",
      "wsct-id-3"
    ],
    "remediationInstructions": "",
    "iacMatchers": []
  }
}


def query_wiz_api(query, variables):
    """Query WIZ API for the given query data schema"""
    data = {"variables": variables, "query": query}

    try:
        # Uncomment the next first line and comment the line after that
        # to run behind proxies
        # result = requests.post(url="https://api.us20.app.wiz.io/graphql",
        #                        json=data, headers=HEADERS, proxies=proxyDict)
        result = requests.post(url="https://api.us20.app.wiz.io/graphql",
                               json=data, headers=HEADERS)

    except Exception as e:
        if ('502: Bad Gateway' not in str(e) and
                '503: Service Unavailable' not in str(e) and
                '504: Gateway Timeout' not in str(e)):
            print("<p>Wiz-API-Error: %s</p>" % str(e))
            return(e)
        else:
            print("Retry")

    return result.json()


def request_wiz_api_token(client_id, client_secret):
    """Retrieve an OAuth access token to be used against Wiz API"""
    auth_payload = {
      'grant_type': 'client_credentials',
      'audience': 'wiz-api',
      'client_id': client_id,
      'client_secret': client_secret
    }
    # Uncomment the next first line and comment the line after that
    # to run behind proxies
    # response = requests.post(url="https://auth.app.wiz.io/oauth/token",
    #                         headers=HEADERS_AUTH, data=auth_payload,
    #                         proxies=proxyDict)
    response = requests.post(url="https://auth.app.wiz.io/oauth/token",
                             headers=HEADERS_AUTH, data=auth_payload)

    if response.status_code != requests.codes.ok:
        raise Exception('Error authenticating to Wiz [%d] - %s' %
                        (response.status_code, response.text))

    try:
        response_json = response.json()
        TOKEN = response_json.get('access_token')
        if not TOKEN:
            message = 'Could not retrieve token from Wiz: {}'.format(
                    response_json.get("message"))
            raise Exception(message)
    except ValueError as exception:
        print(exception)
        raise Exception('Could not parse API response')
    HEADERS["Authorization"] = "Bearer " + TOKEN

    return TOKEN


def main():

    print("Getting token.")
    request_wiz_api_token(client_id, client_secret)

    result = query_wiz_api(query, variables)
    print(result)  # your data is here!




if __name__ == '__main__':
    main()