import hashlib
import os
import sys
from pip._vendor import requests


APIkey='a678eb93430edf821dd72c0dda6f08a616fb3f6be360a18a2926824fdba9ec72'

# Create MD5 hash
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

#parameters: VirusTotal API key and files hash
#return: json include the VirusTotal respons
def VT_Request(key, hash):
    params = {'apikey': key, 'resource': hash}
    url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    return  url.json()



def subDirScanner(path):
    responselist=[]
    isOK=True
    #Get the full path of each file in folder and sub folder
    for root, subFolders, files in os.walk(path):
        for file in files:
            filePath = os.path.join(root, file)
            #Get the files hash
            filehash= md5(filePath)
            # Send hash to VirusTotal
            json_response = VT_Request(APIkey, filehash)
            response = int(json_response.get('response_code'))
            # 1 means the file is unknown or malicious
            if response == 1:
                positives = int(json_response.get('positives'))
                if positives > 0: # There is more then 0 services found this file malicious
                    isOK = False
                    responselist.append(file + ' is malicious. Hit Count:' + str(positives))
                    responselist.append({'details':json_response.get('scans')})
    #If there is no malicious files return 'OK' else return scan details
    if isOK:
        return 'OK'
    else:
        return responselist.json


##################################### TEST MAIN #################################################
print subDirScanner(sys.argv[1])

