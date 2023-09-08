import logging
import json
import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    have_vault_name = False
    have_secret_name = False
    error_retrieving_secret = False
    try:
        req_body = req.get_json()
        print(req_body)
    except ValueError:
         pass
    else:
        #Get Vault name from body
        vault_name = req_body["data"][0][1]
        logging.info(f'Got value {vault_name} for vault_name from request body.')
        have_vault_name = True
    try:
        req_body = req.get_json()
    except ValueError:
        pass
    else:
        #Get Secret name from body
        secret_name = req_body["data"][0][2]
        logging.info(f'Got value {secret_name} for secret_name from request body.')
        have_secret_name = True
    if have_vault_name & have_secret_name:
        logging.info('Have both variables required.')
        #setup keyvault
        KVUri = f"https://{vault_name}.vault.azure.net"
        #get credentials and setup client objects
        credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)
        logging.info('Have Azure credentials.')
        #create secret client using credentials and key vault URI
        secret_client = SecretClient(vault_url=KVUri,
        credential=credential)
        logging.info('Have secret_client')
    
        #Get Secret
        try:
            secret_value = secret_client.get_secret(secret_name).value
            logging.info('Have secret value')
        except BaseException as err:
            logging.error(f"ERROR getting secret {err}")
            error_retrieving_secret = True
        if not error_retrieving_secret:
            #create return body
            return_value = []
            row_to_return = [0, secret_value]
            return_value.append(row_to_return)
            json_compatible_string_to_return = json.dumps( { "data" :
            return_value } )
            logging.info(f'Returning {json_compatible_string_to_return}')
            return func.HttpResponse(json_compatible_string_to_return)
        else:
            return_value = []
            row_to_return = [0, "ERROR no secret"]
            return_value.append(row_to_return)
            json_compatible_string_to_return = json.dumps( { "data" :
            return_value } )
            logging.info(f'Returning {json_compatible_string_to_return}')
            return func.HttpResponse(json_compatible_string_to_return)
    else:
        return_value = []
        row_to_return = [0, "ERROR insufficient parameters"]
        return_value.append(row_to_return)
        json_compatible_string_to_return = json.dumps( { "data" :
        return_value } )
        logging.info(f'Returning {json_compatible_string_to_return}')
        return func.HttpResponse(json_compatible_string_to_return)