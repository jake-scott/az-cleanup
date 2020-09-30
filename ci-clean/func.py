import datetime
import logging
import os
import pprint
import dateutil.parser
import datetime
import time
import re
import requests

import azure.functions as func

from azure.identity import DefaultAzureCredential
import azure.mgmt.resource as azr

## To run in development set the following environment variables:
#   AZURE_CLIENT_ID
#   AZURE_CLIENT_SECRET
#   AZURE_TENANT_ID

## Optionally supply :
#   subscriptions           Comma separated list of subscription IDs
#   max_rg_age              Max age of a RG that doesn't have an expiry date
#   datadog_api_key         Datadog API key for sending events
#

regex = re.compile(r'((?P<days>\d+?)d)?((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?')
defaultRgAge = "7d"

def main(mytimer: func.TimerRequest) -> None:
    maxRgAge = os.getenv("max_rg_age", defaultRgAge)

    ## Default Azure SDK is very verbose..
    azLogger = logging.getLogger("azure")
    azLogger.setLevel(logging.WARN)

    ## Get creds from the environment or MSI
    credentials = DefaultAzureCredential()

    ## Get subscription list from environment, or use all subs in the tenant
    subscriptionIds = os.getenv("subscriptions")
    if subscriptionIds is None:
        logging.info("Querying for all subscription IDs")
        subscriptionIds = list_subscriptions(credentials)
    else:
        logging.info("Using provided list")
        subscriptionIds = [x.strip()  for x in subscriptionIds.split(",")]

    ## Iterate the subscriptions
    tasks = []
    for sub in subscriptionIds:
        logging.info("Cleaning subscription %s" % sub)

        ## Find RGs that we need to remove
        allRgs = list_resource_groups(credentials, sub)
        toClean = filter_resource_groups(allRgs, maxRgAge)

        for rg in toClean:
            task = clean_rg(credentials, sub, rg)
            if task:
                tasks.append(task)

    ## Wait for tasks to complete
    while len(tasks) > 0:
        time.sleep(10)
        tasks[:] = [x for x in tasks if not x.done()]
        logging.info("Still waiting for %d RG deletions", len(tasks))

    logging.info("Delete tasks have completed")


def clean_rg(credentials, subscriptionId, rg):
    logging.info("Cleaning RG %s/%s" % (subscriptionId, rg))
    datadog_event( {
      'alert_type': 'info',
      'source_type_name': 'AZURE',
      'text': "Deleting resource group %s" % rg["Name"],
      'title': 'Azure RG Cleanup',
      'payload': rg,
      'tags': rg['Tags']
    })

    with azr.ResourceManagementClient(credentials, subscriptionId) as rg_client:
        try:
            return rg_client.resource_groups.begin_delete(rg["Name"])

        except Exception as e:
            logging.error("encountered: {0}".format(str(e)))


def filter_resource_groups(allRGs, maxRgAge):
    toClean = []

    for rg in allRGs:
        if is_rg_permenant(rg) == False  and  is_rg_expired(rg, maxRgAge):
                toClean.append(rg)

    return toClean

def is_rg_permenant(rg):
    if "durability" in rg["Tags"]:
        res = rg["Tags"]["durability"] == "permenant"
        logging.info("RG %s is%spermenant" % (rg["Name"], " " if res else " not "))
        return 
    
    logging.info("RG %s does not have a durability tag" % rg["Name"])
    return False

def is_rg_expired(rg, maxRgAge):
    createdOn = None
    expiresOn = None

    maxDelta = parse_time(maxRgAge)
    now = datetime.datetime.now(datetime.timezone.utc)

    if "createdate" in rg["Tags"]:
        createdOn = dateutil.parser.parse(rg["Tags"]["createdate"])

    if "expiredate" in rg["Tags"]:
        expiresOn = dateutil.parser.parse(rg["Tags"]["expiredate"])


    if expiresOn != None:
        if now > expiresOn:
            logging.info("RG %s has expired" % rg["Name"])
            return True
        else:
            logging.info("RG %s has not yet expired" % rg["Name"])
            return False

    if createdOn != None:
        if now > (createdOn + maxDelta):
            logging.info("RG %s is older than max lifetime (%s)" % (rg["Name"], maxDelta))
            return True
        else:
            logging.info("RG %s is not yet older than max lifetime (%s)" % (rg["Name"], maxDelta))
            return False

    logging.warn("RG %s is missing 'expiredate' and 'createdate' tags, ignoring" % rg["Name"])

    return False


def process_rg_instance(group):
    """
    Get the relevant pieces of information from a ResourceGroup instance.
    """
    return {
        "Name": group.name,
        "Id": group.id,
        "Location": group.location,
        "Tags": group.tags,
        "Properties": group.properties.provisioning_state if group.properties and group.properties.provisioning_state else None
    }

def list_resource_groups(credentials, subscriptionId):
    list_of_resource_groups = []

    with azr.ResourceManagementClient(credentials, subscriptionId) as rg_client:
        try:
            for i in rg_client.resource_groups.list():
                list_of_resource_groups.append(process_rg_instance(i))

        except Exception as e:
            logging.error("encountered: {0}".format(str(e)))

    return list_of_resource_groups

def list_subscriptions(credentials):
    list_of_subscriptions = []

    with azr.SubscriptionClient(credentials) as s_client:
        try:
            for s in s_client.subscriptions.list():
                list_of_subscriptions.append(s.subscription_id)

        except Exception as e:
            logging.error("encountered: {0}".format(str(e)))

    return list_of_subscriptions

def parse_time(time_str):
    parts = regex.match(time_str)
    if not parts:
        return

    parts = parts.groupdict()
    time_params = {}

    for name, param in parts.items():
        if param:
            time_params[name] = int(param)

    return datetime.timedelta(**time_params)


def datadog_event(data):
    key = os.getenv("datadog_api_key", None)
    if not key:
        return

    url = "https://api.datadoghq.com/api/v1/events"
    headers = {
        'DD-API-KEY': key
    }

    resp = requests.post(url, json=data, headers=headers)
    logging.info("Datadog response: %s" % resp.content)

