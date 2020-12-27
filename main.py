import requests
from winregistry import WinRegistry as Reg
import json
import simplecrypt
import base64
import os
import time
import threading
from pathlib import Path


GlobalAstatus = "Available"

def LastNlines(fname, N):
    lines = ""
    try:
        with open(fname) as file:
            for line in (file.readlines()[-N:]):
                lines = lines + line
    except IOError:
        print("[-] "+fname+" file not accessible")

    return lines


def executeHascat(command, AgentID):
    os.popen("cd hashcat & " + command).read()
    exit(1)

def hashcatError(AgentID, report):
    url = serverIP + "api?call=crack"
    data = {
        "status": "Unable",
        "agentid": AgentID,
        "report": report
    }
    global GlobalAstatus
    GlobalAstatus = "Unable"
    r = requests.post(url=url, data=data)
    print(r.text)

    exit(1)


def AgentStatus(AgentID):
    url = serverIP + "api?call=crack"
    hash = ""
    wasCracking = False
    while(True):
        print("[+] Status: Standby")
        time.sleep(60)
        if (threading.active_count() < 2 and wasCracking == False):
            data = {
                "status": GlobalAstatus,
                "agentid": AgentID
            }
            r = requests.post(url=url, data=data)
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
                        if(jsonData['attacktype'] == "dictionary" and jsonData['command'] != None):
                            print("Dictionary Attack")
                            command = jsonData['command']
                            for root, dirs, files in os.walk("wordlists"):
                                for name in files:
                                    if name.endswith(".txt"):
                                        command = command+" ..\\"+os.path.join(root,name)
                            command = command+" > result.log"
                            t = threading.Thread(target=executeHascat, name="Recovering hash",
                                                 args=(command, AgentID,))

                            hash = jsonData['hash']
                            t.daemon = True
                            t.start()
                            wasCracking = True
                        elif(jsonData['attacktype'] == "bruteforce" and jsonData['command'] != None):
                            print("[+] Recovering password")
                            t = threading.Thread(target=executeHascat, name="Recovering hash", args=(jsonData['command'],AgentID,))

                            hash = jsonData['hash']
                            t.daemon = True
                            t.start()
                            status = ""

                            #lines = LastNlines("result.log", 50)

                            if("Status...........: Cracked" in status):
                                encryptedLog = simplecrypt.encrypt(AgentID, status)
                                encryptedB64 = base64.b64encode(encryptedLog)
                                data = {
                                    "status": GlobalAstatus,
                                    "agentid": AgentID,
                                    "log": encryptedB64,
                                    "hash": jsonData['hash']
                                }
                                r = requests.post(url=url, data=data)

                    except simplecrypt.DecryptionException:
                        print("Bad Agent")
        else:
            if(wasCracking):
                CrackResult(AgentID, hash, url)
                wasCracking = False
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


def CrackResult(AgentID, hash, url):
    potFile = Path("hashcat/hashcat.potfile")
    if potFile.is_file():
        os.remove(potFile)
    try:
        f = open("hashcat/result.log", "r")
        try:
            if "[s]tatus [p]ause [b]ypass" in f.read():
                f.close()
                lines = LastNlines("hashcat/result.log", 50)
                encryptedLog = simplecrypt.encrypt(AgentID, lines)
                encryptedB64 = base64.b64encode(encryptedLog)
                data = {
                    "status": GlobalAstatus,
                    "agentid": AgentID,
                    "log": encryptedB64,
                    "hash": hash
                }
                r = requests.post(url=url, data=data)
            else:
                print("Error")
                hashcatError(AgentID, f.read())
        finally:
            f.close()
    except IOError:
        print("In Progress")

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
