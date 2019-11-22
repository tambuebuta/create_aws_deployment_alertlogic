#!/usr/bin/python3 -u

#Required Libraries
import json
import requests
import getpass
import argparse
import time
from datetime import datetime

#Read in configuration file
from Create_Deployment_Configuration import *

#Set global URL's
global_url= 'https://api.global.alertlogic.com/'

#Header just to make the script look prettier
print('''
====================================================================================================

              :ydho`                 Title:     Create_Deployment.sh
            +ddddd:                 Author:     Alert Logic Deployment Services
           .ddddh+             Description:     A tool for creating deployments
           yddy/``                              into the Alert Logic UI for 
          +dh:   +/                             your chosen Customer ID
         +dy` ''',end='')
print('``',end='')
print('''  sy-          
       `odh.''',end='')
print('-/+++-', end='')
print('''.dd+`        
      .yddo ''',end='')
print(':++++/',end='')
print(''' sddy-            Usage:      python3 Create_Deployment.py
     /hddd/  ''',end='')                
print('.::-',end='')
print('''  sdddh/                
    /ddddd-        oddddd.           Note:      Ensure that all required fields in the configuration 
    +dddds         .hdddh`                      file have been input. For any assistance, please 
     .::.            -:-`                       contact Alert Logic Deployment Services                

====================================================================================================
''')

if cid == '':
	print ('\nNo CID stored in order for us to deploy. Please input required fields in the configuration file\n')
	exit()
#Function to get AIMS Token once we have creds
def get_token_userpass ():
	url = '{}aims/v1/authenticate'.format(global_url)
	global auth_token
	#Get credentials
	print('Please enter Alert Logic Console Credentials:')
	aims_user = input(" Username: ")
	aims_pass = getpass.getpass(" Password: ")
	
	if "alertlogic.com" in aims_user : 
		print ('\nAlert Logic User Detected. Cannot authenticate since MFA is mandatory. Use API Keys.\n')
		exit()
	
	print('\nValidating credentials...', end = '')
	
	#POST request to the URL using credentials. Load the response into auth_info then parse out the token
	token_response = requests.post(url, auth=(aims_user, aims_pass))
	
	if token_response.status_code != 200: 
		print('There was an error. Got the following response: ',end='') 
		print(token_response)
		print()
		exit()
	
	auth_info = json.loads(token_response.text)
	auth_token = auth_info['authentication']['token']

#Same as previous, but uses stored API Keys if they are detected
def get_token_apikey ():
	url = '{}aims/v1/authenticate'.format(global_url)
	global auth_token
	print('Detected stored API Keys. Validating...', end = '')
	#POST request to the URL using keys. Load the response into auth_info then parse out the token
	token_response = requests.post(url, auth=(access_apikey, secret_apikey))
	
	if token_response.status_code != 200: 
		print('There was an error. Got the following response: ',end='') 
		print(token_response)
		print()
		exit()
	
	auth_info = json.loads(token_response.text)
	auth_token = auth_info['authentication']['token']

#Function to validate the AIMS token was successfully generated, and that it has not expired
def validate_token ():
	url = '{}aims/v1/token_info'.format(global_url)
	headers = {'x-aims-auth-token': '{}'.format(auth_token)}
	global validate_info
	validate_response = requests.get(url, headers=headers)
	validate_info = json.loads(validate_response.text)
	
	#get current unix timestamp
	current_time = int(time.time())
	#get token expiration timestamp
	token_expiration = validate_info['token_expiration']
	num_seconds_before_expired=(token_expiration - current_time)
	
	if num_seconds_before_expired < 0 :
		print(' Could not generate / validate AIMS Token. Please check credentials and try again\n')
		exit()
	else :
		print(' AIMS token generated and validated.\n')
		time.sleep(1)

if access_apikey != '' and secret_apikey != '':
	get_token_apikey()
	validate_token()
elif username != '' and password != '':
	get_token_userpass()
	validate_token()
else: 
		print ('\nNo credentials stored in order to authenticate against aims.\n')
		exit()
#Authentication complete

headers = {"x-aims-auth-token": "{}".format(auth_token)} #Set header for all future API calls

#Get base endpoint for customer ID
endpoint_url = '{0}endpoints/v1/{1}/residency/default/services/assets/endpoint/api'.format(global_url, cid)
endpoint_response = requests.get(endpoint_url, headers=headers)
endpoint_info = json.loads(endpoint_response.text) 
base_url = endpoint_info['assets']
base_url = 'https://' + base_url

#Get CID that the token exists in (CID the authenticated user was in). Then check if that CID is authorised to view 
users_CID = validate_info['user']['account_id']

#Print out authenticated user information
print('Authenticated Users Info:\n')
user_name = validate_info['user']['name']
user_email = validate_info['user']['email']
user_role = validate_info['roles'][0]['name']
user_lastlogin_unix = validate_info['user']['user_credential']['last_login']
user_lastlogin_hr = datetime.utcfromtimestamp(user_lastlogin_unix ).strftime('%d/%m/%Y %H:%M:%S %Z')
print('    Name: ' + user_name)
print('    Email: ' + user_email)
print('    User Role: ' + user_role) 
print('    CID: ' + users_CID)
#print('    Last authentication: ' + user_lastlogin_hr) #Don't think this is needed, last time user logged into the UI
print()


#If the CID the user has authenticated from, is not equal to the target CID
if cid != users_CID: 
	#This is checking whether there is a managed relationship (ensuring a parent-child relationship) between the 2 CID's. 
	managed_CID_check_url = '{0}aims/v1/{1}/accounts/managed/{2}'.format(global_url, users_CID, cid)
	managed_CID_check_response = requests.get(managed_CID_check_url, headers=headers)
	managed_CID_check_statuscode = managed_CID_check_response.status_code
	
	#1 - Make sure the CID's have a managed relationship (Status Code 204 is a success response)
	if managed_CID_check_statuscode != 204:
		print(' Authenticated user does not have authorisation to perform actions in CID ' + cid + ' Please try another user.\n')
		exit()
	
	#2 - If yes to step 1, make sure authenticated user has permissions to create stuff in target CID
	if user_role == 'Read Only' or user_role == 'Support/Care' or user_role == 'Power User' :
		print ('Authenticated user does not have the required permission to create in CID ' + cid)
		print ('\n    User must be Administrator or Owner\n')
		exit()

#If the CID the user has authenticated from, is equal to the target CID
elif cid == users_CID:
	# Make sure the autenticated user has permission to create in target CID
	if user_role == 'Read Only' or user_role == 'Support/Care' :
		print ('Authenticated user does not have the required permission to create in CID ' + cid)
		print ('\n    User must be Administrator, Owner or Power user\n')
		exit()

#Get some account information from the CID
print('Target CID Info:\n')
account_info_url = '{0}aims/v1/{1}/account'.format(global_url, cid)
account_info_response = requests.get(account_info_url, headers=headers)
account_info = json.loads(account_info_response.text)
account_name = account_info['name']
account_CID = cid
account_defaultloc = account_info['default_location']
print('    Account Name: ' + account_name)
print('    Accound CID: ' + account_CID)
print('    Default Location: ' + account_defaultloc)
print('    Base URL: ' + base_url)
print()

### Continue to rest of script. 

#Temp - Creating credentials works 
def create_credentials (): 

	payload = {
		"name": cid +" discover cred",
		"secrets": {
		"type": "aws_iam_role",
		"arn": role_arn
		}
	}
	
	create_payload=json.dumps(payload)
	create_cred_url = '{0}/credentials/v2/{1}/credentials'.format(base_url, cid)
	create_cred_response = requests.post(create_cred_url, create_payload, headers=headers)
	create_cred_info = json.loads(create_cred_response.text)
	credential_id = create_cred_info['id']

	return credential_id

#Temp - Creating deployment doesn't work so far. The enabled = true is what is failing 
def create_deployment ():

	deployment_payload = {
		"name": aws_id,
		"platform": {
			"type": "aws",
			"id": "'$aws_id'",
			"monitor": {
				"enabled": enabled,
				"ct_install_region": "'$cd_install_region'"
			}
		},
		"mode": mode,
		"enabled": enabled,
		"discover": enabled,
		"scan": true,
		"scope": {
			"include": [scope]
		},
		"cloud_defender": {
			"enabled": false,
			"location_id": account_defaultloc
		},
		"credentials": [{
			"id": credential_id,
			"purpose": "discover",
			"version": "2018-01-01"
		}]
	}
	
	create_deployment_payload=json.dumps(deployment_payload)
	create_deployment_url = '{0}/deployments/v1/{1}/deployments'.format(base_url, cid)
	create_deployment_response = requests.post(create_deployment_url, create_deployment_payload, headers=headers)
	create_deployment_info = json.loads(create_deployment_response.text)
	print("----------------------")
	print (create_deployment_info)
	print("----------------------")
	
print("Creating Credentials")
create_credentials()
print("Creating Deployment")
create_deployment()