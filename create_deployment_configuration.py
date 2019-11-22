############################################################
#####  Configuration settings for Deployment Creation  #####
############################################################

# This configuration file is used to set all required 
# variables in order to create an aws deployment into 
# an Alert Logic Customer ID. 

## Pre-requisites: 
# 1) Cross Account Role for the AWS account set up, and role ARN obtained - 
	# For more information on setting up this Cross Account role, see 
	# the following links: 
	# Full Permission: https://docs.alertlogic.com/prepare/aws-full-permission-deployment.htm
	# Minimal Permission: https://docs.alertlogic.com/prepare/aws-minimal-permission-deployment.htm

## Authentication Information
# Here you can specify either a username/password, or 
# access/secret keys (that can be generated through the 
# Alert Logic Console), in order to obtain an authentication 
# token to authorise all following API requests. The script 
# will use API Keys first if they are present 

# The Username & Password you would like to use for authentication: 
#username = ''
#password = ''

# The API Keys you would like to use for authentication: 
access_apikey = ''
secret_apikey = ''

## Main Configuration
# The Alert Logic Customer ID you would like to create the deployment into: 
cid = ""

#The role ARN of the Cross Account Role, for this AWS account:
role_arn = ""
aws_id = ""

#Manual/Automatic
mode = "manual" 
enabled = "true"
#comma seperated list of regions (example)
regions = ""

#comma seperated list of VPC's (example) 
vpcs = ""