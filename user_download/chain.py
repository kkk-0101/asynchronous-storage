import requests
from flask import json
from pack import _tyke


def query_chain(id, i):
    key_chain = str(id)
    print("=========== 根据HASH查询：", key_chain, " ===========")
    response = requests.get(url='http://182.254.135.172:9090/fabric/getData', params={"key": key_chain})
    fileDict = json.loads(response.content.decode('utf-8'))
    try:
        fileMetaData = json.loads(fileDict["value"])
        if fileDict['code'] != 200:
            print("0-File retrieval failure")
        else:
            print(fileMetaData['Encryption method'])
            tyke = _tyke(fileMetaData['Encryption method'])
            cACL = fileMetaData["ACL"]
            chm_b = fileMetaData['key'].encode("ISO-8859-1")
            tx = {"tyke": tyke, "cACL": cACL, "chm_b": chm_b}
            return tx
    except Exception as e:
        print(e)
        print("2-File retrieval failure")
