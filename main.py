import requests
from winregistry import WinRegistry as Reg
import json
import simplecrypt
import base64
import os, sys
import time
import threading
from pathlib import Path
from inspect import getsourcefile
from os.path import abspath
import inspect
import configparser
import subprocess

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
    path = os.path.abspath(os.path.dirname(sys.argv[0]))
    if(path[:1] != os.getcwd()[:1]):
        os.chdir(path[:2])
        os.chdir(path)
    os.chdir("hashcat")
    os.popen(command)
    os.chdir("../")

def changeDir():
    path = os.path.abspath(os.path.dirname(sys.argv[0]))
    if (path[:1] != os.getcwd()[:1]):
        os.chdir(path[:2])
        os.chdir(path)
    return os.getcwd()

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
    return 0


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
            jsonData = ""
            try:
                jsonData = json.loads(r.text)
            except:
                print("[-] Something went wrong")
            if(jsonData != ""):
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
                hashcatError(AgentID, f.read())
        finally:
            f.close()
    except IOError:
        print("[+] In Progress")

def agentVersion():
    config = configparser.ConfigParser()
    config.read("version.ini")
    agentversion = config.get("configuration", "agentversion")
    dictionaryversion = config.get("configuration", "dictionaryversion")
    hashcatversion = config.get("configuration", "hashcatversion")
    url = serverIP + "api?call=crack&request=version"
    r = requests.get(url=url)
    jsonData = ""

    currentDir = changeDir()

    newUpdate = False
    try:
        jsonData = r.json()
        print("[+] Checking for new update")
        if(agentversion != jsonData['agentversion']):
            newUpdate = True

        if(dictionaryversion != jsonData['dictionaryversion']):
            newUpdate = True

        if (hashcatversion != jsonData['hashcatversion']):
            newUpdate = True

        if(newUpdate):
            subprocess.Popen("updater.exe")

        return 0
    except:
        print("[-] Failed to check for new update")
        return -1
    if(jsonData != ""):
        print("[-] Could not read server response")
        return -1

def main():
    agentVersion()
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
        url = serverIP+"api?call=crack&request=install&o=zlsdkhLbAzdz88xx79r783s3vzanfmzz3"
        r = requests.get(url=url)
        jsonData = ""
        try:
            jsonData = r.json()
        except:
            print("[-] Something went wrong")

        reg.create_key(keyPath+r"\NAgent")
        #HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        reg.write_value(keyPath+r"\NAgent", 'NAgentID', jsonData['AgentID'], 'REG_SZ')
        currentDir = os.getcwd()
        reg.write_value(keyPath+r"\Microsoft\Windows\CurrentVersion\Run", 'NAgent', currentDir+r'\NAgent.exe', 'REG_SZ')
        AgentStatus(jsonData['AgentID'])

serverIP = "http://www.neehack.com/"

main()
