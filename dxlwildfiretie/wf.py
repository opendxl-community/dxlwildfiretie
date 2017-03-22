import requests
import json
import os
import sys
import logging
import pprint

import xml.etree.ElementTree as et
import ConfigParser
from datetime import datetime, timedelta

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel, FileProvider


# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Create config information for WildFire
wfConfig = ConfigParser.ConfigParser()
wfConfig.read(WF_CONFIG_FILE)



# For each hash, a unique API call to WildFire is made to resolve filename. 
# This can quickly consume the limited number of API calls allowed in cloud
# services.

# For now, assume not resolving hashes to filenames... default filename is WildFire.unknown
RESOLVE_FILENAME = wfConfig.get("wildfire", "resolve_filename")
WILDFIRE_APIKEY = wfConfig.get("wildfire", "apikey")
WILDFIRE_CHANGED_AGE = int(wfConfig.get("wildfire", "wf_age"))
# NOTE: The WF cloud has a bug which return ALL submissions
#       beyond what is related to the account associated with the 
#       API key. So, be aware that 10's of thousands of entries
#       can sworm your TIE server if you enable for WF Cloud
WILDFIRE_API_HOST = wfConfig.get("wildfire", "wf_host")

#Changed since needs to be date format. We are pulling in # of days.
# So, we need to take today's date and go back age
WILDFIRE_CHANGED_SINCE = "{:%Y-%m-%d}".format(datetime.today() - timedelta(days=WILDFIRE_CHANGED_AGE))


form = {
        "apikey":WILDFIRE_APIKEY,
        "date":WILDFIRE_CHANGED_SINCE
        }



strWFResult = requests.post(WILDFIRE_API_HOST + '/publicapi/get/verdicts/changed',form).text.encode('utf-8').strip()

tree=et.fromstring(strWFResult)

WFResult = {}
childcounter=0

for el in tree.findall('get-verdict-info'):
    # Unset 
    tmpVerdict = None
    tmpSHA256 = None
    tmpMD5 = None
    reportForm = None
    strReportResult = None

    # loop through each result to identify which 
    # results have a verdict that should be in scope.
    for ch in el.getchildren():
        if ch.tag == "verdict":
            tmpVerdict = ch.text
        elif ch.tag == "sha256":
            tmpSHA256 = ch.text
        elif ch.tag == "md5":
            tmpMD5 = ch.text

    # Build a dictionary of results that should be in scope for updating TIE
    # 1 = malware, 0 = benign, 2 = grayware, -100 = pending, -101 = error, -102 = unknown
    if tmpVerdict == "1":
        WFResult[childcounter] = {}
        WFResult[childcounter]['verdict']=tmpVerdict
        WFResult[childcounter]['md5']=tmpMD5
        WFResult[childcounter]['sha256']=tmpSHA256
        WFResult[childcounter]['trustlevel']=TrustLevel.MOST_LIKELY_MALICIOUS

        # limit the number of resolutions for testing
        
        """
        # for now, there is no good way to pull the filename from wildfire
        # Will update source code whats the WF API resolves this issue
        if RESOLVE_FILENAME:
            #do some stuff here to query reports API to garner filename
            reportForm = {
                    "apikey":WILDFIRE_APIKEY,
                    "hash":tmpSHA256
                    }



            strReportResult = requests.post(WILDFIRE_API_HOST + '/publicapi/get/report',reportForm).text.encode('utf-8').strip()

            treeReport=et.fromstring(strReportResult)
            for elReport in treeReport.iter('apk_api'):
                apkSet=1
                break
    
    
            if apkSet == 0:
                print str(childcounter)
                print strReportResult
                exit()

       """
         
        WFResult[childcounter]['filename'] = "WILDFIRE.unknown"
        
        childcounter+=1



# Loop through each file and check with the TIE Server to determine if
# it already exists.


with DxlClient(config) as client:

    #Connect to DXL fabric
    client.connect()

    #Create TIE Client
    tie_client=TieClient(client)

    
    for fileKey in WFResult:
        #unset reusables
        reputations_dict = None
        currentMD5 = None
        currentSHA256 = None
        currentFilename = None
        currentTrustLevel = None        

        currentMD5= WFResult[fileKey]['md5']
        currentSHA256=WFResult[fileKey]['sha256']
        currentFilename=WFResult[fileKey]['filename']
        currentTrustLevel=WFResult[fileKey]['trustlevel']

        reputations_dict = \
                tie_client.get_file_reputation({
                    HashType.MD5: currentMD5,
                    HashType.SHA256: currentSHA256
                    })

        
        #Check if there is an enterprise (custom set) reputation
        if (reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.NOT_SET and \
            reputations_dict[FileProvider.GTI]["trustLevel"]==TrustLevel.NOT_SET) or \
            reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.UNKNOWN or \
            reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.MIGHT_BE_TRUSTED or \
            reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.MOST_LIKELY_TRUSTED:
            # If not set, go ahead and set it
            tie_client.set_file_reputation(
                currentTrustLevel, {
                    HashType.MD5: currentMD5,
                    HashType.SHA256: currentSHA256},
                filename=currentFilename,
                comment="Reputation set via OpenDXL WildFire Integration")
            print "Reputation set for: " + str(fileKey) + ": " + currentMD5 

        else:
            print "Skipping: " + str(fileKey) + ": " + currentMD5
