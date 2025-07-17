import json
import requests
import os
import boto3
from base64 import b64decode

def lambda_handler(event, context):

    def decrypit(encripted):
        decrypited = boto3.client('kms').decrypt(
        CiphertextBlob=b64decode(encripted),
        EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']})['Plaintext'].decode('utf-8')
        return decrypited
    
    snyk_api_url="https://snyk.io/api/v1"
    cli_ide_role_id = decrypit(os.environ['CLI_IDE_ROLE_ID'])
    auth_token = decrypit(os.environ['SNYK_TOKEN'])
    adp_group_id = decrypit(os.environ['ADP_GROUP_ID'])

    headers = {
        "Authorization": f"token {auth_token}",
        "Content-Type": "application/vnd.api+json"
    }

    #List all orgs and get ADP_general ID
    org_url = f"{snyk_api_url}/orgs"
    snyk_orgs = requests.get(org_url, headers=headers)

    adp_general_id = None # adp_general ORG

    for org in snyk_orgs.json().get('orgs', []):
        if org.get('name') == 'ADP_GENERAL':
            adp_general_id = org.get('id')
            break

    #Get all ADP group members and identify the ones without a ORG
    adp_members = requests.get(f"{snyk_api_url}/group/{adp_group_id}/members", headers=headers)
    #print(json.dumps(adp_members.json(), indent=4))

    for member in adp_members.json():
        email = None
        if not member.get('orgs'):
            user_id = member.get('id')

            print(f"Member {member.get('name')} does not have any orgs, adding to ADP_GENERAL org")

            #Add users that are not associated with an org to ADP_General org
            url = f"https://api.snyk.io/rest/orgs/{adp_general_id}/memberships?version=2024-10-15"

            payload = {
                      "data": {
                        "relationships": {
                          "org": {
                            "data": {
                              "id": adp_general_id,
                              "type": "org"
                            }
                          },
                          "role": {
                            "data": {
                              "id": cli_ide_role_id,
                              "type": "org_role"
                            }
                          },
                          "user": {
                            "data": {
                              "id": user_id,
                              "type": "user"
                            }
                          }
                        },
                        "type": "org_membership"
                      }
                    }

            response = requests.post(url, headers=headers, json=payload)
            print(response.text)
            print(response.status_code)

    
    
