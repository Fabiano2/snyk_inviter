import json
import requests
import logging
import os
import boto3
from base64 import b64decode

"""
This code is ready to run on a AWS Lambda Function, but can be easily modified to run on other platforms
"""


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
def lambda_handler(event, context):

    def decrypit(encripted):
        decrypited = boto3.client('kms').decrypt(
        CiphertextBlob=b64decode(encripted),
        EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']})['Plaintext'].decode('utf-8')
        return decrypited
    
    snyk_url = "https://snyk.io/api/v1"
    snyk_token = decrypit(os.environ['SNYK_TOKEN'])
    adp_group_id = decrypit(os.environ['ADP_GROUP_ID'])
    
    headers = {
        "Authorization": f"token {snyk_token}",
        "Content-Type": "application/json"
    }
    org_url = f"{snyk_url}/orgs"
    snyk_orgs = requests.get(org_url, headers=headers)
    
    
    if snyk_orgs.status_code != 200:
        logger.info(f"❌ Error to query orgs: {snyk_orgs.status_code} - {snyk_orgs.text}")
        exit()
    
    adp_general_id = None # adp_general ORG
    
    for org in snyk_orgs.json().get('orgs', []):
        if org.get('name') == 'ADP_GENERAL':
            adp_general_id = org.get('group', {}).get('id')
            break
    
    logger.info(f"ADP_GENERAL ID: {adp_general_id}")
    
    # Get all adp group members
    adp_members = requests.get(f"{snyk_url}/group/{adp_group_id}/members", headers=headers)
    invite_url = f"{snyk_url}/org/{adp_general_id}/invite"
    print("test1")
    for member in adp_members.json():
        email = None
        if not member.get('orgs'):
            logger.info(f"Member: {json.dumps(member, indent=4)}")
            email = member.get('email')
    
            if email:
                payload = json.dumps({"email": email, "isAdmin": False})
                logger.info(f"Payload: {payload}")
                res = requests.post(invite_url,     headers=headers, data=payload)
                if res.status_code == 200:
                    logger.info(f"Invite sent to {email}")
                else:
                    logger.info(f"Error to send invite to {email}: {res.status_code} - {res.text}")
            else:
                logger.info("No email found")
            print("sending email to ", email)
            
    return adp_members.json()
