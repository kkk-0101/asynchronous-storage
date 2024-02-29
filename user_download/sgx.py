import requests
from flask import json

from responseSGX.routes import index


def sgx(tyke, sec_ACL, cACL):
    try:
        url = 'http://39.105.219.78:8000/sgx'
        data = {'tyke': tyke, 'sec_ACL': sec_ACL, 'cACL': cACL}
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=json.dumps(data), headers=headers)
        data = response.json()
        print("Access SGX successfully")
        return data["Flag"]
    except:
        print("Unable to access SGX===")
        response = index(tyke, sec_ACL, cACL)
        return response
        return False