import requests
from winregistry import WinRegistry as Reg
import json
import simplecrypt
import base64
import os
import time
import threading

def LastNlines(fname, N):
    lines = ""
    try:
        with open(fname) as file:
            for line in (file.readlines()[-N:]):
                lines = lines + line
    except IOError:
        print("[-] "+fname+" file not accessible")

    return lines


def executeHascat(command):
    status = os.popen("cd hashcat & " + command).read()
    print("[+] Password recovery completed")
    return status


def AgentStatus(AgentID):
    url = serverIP + "api?call=crack"
    hash = ""
    while(True):
        print("[+] Status: Standby")
        time.sleep(6)
        if (threading.active_count() < 2):

            data = {
                "status": "Available",
                "agentid": AgentID
            }
            r = requests.post(url=url, data=data)
            print(r.text)
            jsonData = json.loads(r.text)

            for key, value in jsonData.items():
                if("action" == key):
                    print("[+] Status: "+jsonData['status'])
                    value = value[2:]
                    value = value[:-1]
                    value = bytes(value, encoding="utf-8")
                    actionb64Decode = base64.b64decode(value)
                    print("[+] Decrypting Hash")
                    try:
                        decryptData = simplecrypt.decrypt(AgentID, actionb64Decode).decode('utf-8')
                        jsonData = json.loads(decryptData)
                        if(jsonData['command'][:7] == "hashcat"):
                            print("[+] Recovering password")
                            t = threading.Thread(target=executeHascat, name="Recovering hash", args=(jsonData['command'],))
                            hash = jsonData['hash']
                            t.daemon = True
                            t.start()
                            status = ""
                            #lines = LastNlines("result.log", 50)

                            if("Status...........: Cracked" in status):
                                encryptedLog = simplecrypt.encrypt(AgentID, status)
                                encryptedB64 = base64.b64encode(encryptedLog)
                                data = {
                                    "status": "Available",
                                    "agentid": AgentID,
                                    "log": encryptedB64,
                                    "hash": jsonData['hash']
                                }
                                r = requests.post(url=url, data=data)
                            os.system("del hashcat\\hashcat.potfile")
                    except simplecrypt.DecryptionException:
                        print("Bad Agent")
        else:
            print("[+] Updating status")
            url = serverIP + "api?call=crack&status=busy"
            data = {
                "status": "Busy",
                "agentid": AgentID,
                "hash": hash
            }
            r = requests.post(url=url, data=data)
            lines = LastNlines("result.log", 10)
            print(lines)


def main():
    reg = Reg()
    keyPath = r"HKLM\Software"
    newInstal = 1
    if('NAgent' in reg.read_key(keyPath)['keys']):
        try:
            CNAgentID = reg.read_value(keyPath + r'\NAgent', 'NAgentID')
            newInstal = 0
            AgentStatus(CNAgentID['data'])
        except OSError as e:
            newInstal = 1

    if(newInstal):
        url = serverIP+"api?crack=install&o=zlsdkfLAAzd388x879378zs3szasfkFJK"
        r = requests.get(url=url)
        jsonData = r.json()
        reg.create_key(keyPath+r"\NAgent")
        reg.write_value(keyPath+r"\NAgent", 'NAgentID', jsonData['AgentID'], 'REG_SZ')
        AgentStatus(jsonData['AgentID'])


serverIP = "http://10.0.0.97:8000/"
main()