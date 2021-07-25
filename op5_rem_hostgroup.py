#!/usr/bin/python3


import csv
import http.client
import json
from urllib.parse import urlencode, quote_plus
from getpass import getpass
import base64
import ssl
import argparse
import os
from array import array


# Create the command line argument parser
parser = argparse.ArgumentParser(description="OP5 API Change Template for Hosts")

# Add the groups for the required and optional command line arguments. Also hide the default grouping
parser._action_groups.pop()
required = parser.add_argument_group('Required Arguments')
optional = parser.add_argument_group('Modifier Arguments')

# Add the command line arguments that are required.
required.add_argument("-u", "--username", help="OP5 API username", type=str, required=True)
required.add_argument("-f", "--file", help="Path to file with hosts to update", type=str, required=True)
required.add_argument("-g", "--hostgroup", help="Name of the hostgroup to be added", type=str, required=True)
# Add the command line arguments that are optional.
optional.add_argument("-s", "--server", help="OP5 Server DNS Name or IP. Defaults to localhost", default="localhost", type=str)
optional.add_argument("-i", "--insecure", help="Allow invalid and self signed SSL Certificates. This argument has no options", action='store_true')

# Parse the arguments into variables.
args = parser.parse_args()

# Determine if we are going to connect accepting any SSL certificate or require validation.
if args.insecure:
    conn = http.client.HTTPSConnection(
        args.server,
        context=ssl._create_unverified_context()
    )
else:
    conn = http.client.HTTPSConnection(
        args.server
    )

# Get the password input from user
apipw=getpass("OP5 API Password:")


# Create the headers to allow authentication and return encoding.
headers = {
    'accept': "application/json",
    'Authorization': 'Basic {auth_string}'.format(auth_string=base64.b64encode(str.encode('{username}:{password}'.format(username=args.username, password=apipw))).decode('utf=8'))
}

headersx = {
    'Accept': "application/xml",
    'Content-Type': "application/xml",
    'Authorization': 'Basic {auth_string}'.format(auth_string=base64.b64encode(str.encode('{username}:{password}'.format(username=args.username, password=apipw))).decode('utf=8'))
}


with open(args.file) as hostsfile:
    host2up=hostsfile.read().splitlines()
for host in range(len(host2up)):
    query4hgs = {
      'format': 'json',
      'query': '[hosts] name="'+host2up[host]+'"',
      'columns':'name,groups'
    }

    
    conn.request("GET", "/api/filter/query?{query}".format(query=urlencode(query4hgs, quote_via=quote_plus)), None, headers)
    res = conn.getresponse()
    hgs = json.loads(res.read())
    if args.hostgroup in hgs[0]['groups']:
        hgs[0]['groups'].remove(args.hostgroup)
        print("Removing hostgroup "+args.hostgroup+" from "+str(hgs[0]['name']))
        payloadbeg = '''<root>
        <param name="hostgroups">'''
        buildpayload=""
        payloadend='''</param>
        </root>'''
        for gi in range(len(hgs[0]['groups'])):
            buildpayload=buildpayload+"<value>"+hgs[0]['groups'][gi]+"</value>"
        payload=payloadbeg+buildpayload+payloadend
        conn.request("PATCH", "/api/config/host/{host2update}".format(host2update=str(hgs[0]['name'])), payload, headersx)
        resup = conn.getresponse()
        if resup.status >= 400:
            print('Server returned status code {status} - {reason}'.format(status=resup.status, reason=resup.reason))
            break
        dataup = resup.read()
    
    else:
        print("Nothing to do. Hostgroup "+args.hostgroup+" is not set for host: "+str(hgs[0]['name']))

conn.request("POST", "/api/config/change?format=json",'',headers)