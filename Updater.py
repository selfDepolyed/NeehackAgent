import requests
from winregistry import WinRegistry as Reg
import json
import base64
import os, sys
import time
from pathlib import Path
from inspect import getsourcefile
from os.path import abspath
import inspect
import configparser
import psutil
import subprocess

def changeDir():
    path = os.path.abspath(os.path.dirname(sys.argv[0]))
    if (path[:1] != os.getcwd()[:1]):
        os.chdir(path[:2])
        os.chdir(path)
    return os.getcwd()


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
    try:
        jsonData = r.json()
        print("[+] Checking for new update")
        Updated = False
        if(agentversion != jsonData['agentversion']):
            newAgentversion = jsonData['agentversion']
            newAgenturl = jsonData['agentdownload']
            PROCNAME = "NAgent.exe"
            for proc in psutil.process_iter():
                # check whether the process name matches
                if proc.name() == PROCNAME:
                    proc.kill()

            if os.path.isfile("NAgent.exe"):
                os.remove("NAgent.exe")
            downloadUpdate(newAgenturl, "NAgent.exe")
            print("[+] Agent Downloaded Successfully")
            config.set("configuration", "agentversion", newAgentversion)
            Updated = True

        if(dictionaryversion != jsonData['dictionaryversion']):
            print("[+] Updating Dictionary, this might take a while")
            newdictionaryversion = jsonData['dictionaryversion']
            newdictionarydownload = jsonData['dictionarydownload']
            if os.path.isfile("wordlists/masterbook.txt"):
                os.remove("wordlists/masterbook.txt")
            downloadUpdate(newdictionarydownload, "wordlists/masterbook.txt")
            config.set("configuration", "dictionaryversion", newdictionaryversion)
            print("[+] Dictionary updated")

        if (hashcatversion != jsonData['hashcatversion']):
            newhashcatversion = jsonData['hashcatversion']
            newhashcatdownload = jsonData['hashcatdownload']
            config.set("configuration", "hashcatversion", newhashcatversion)


        with open("version.ini", 'w') as configfile:
            config.write(configfile)

        if(Updated):
            subprocess.Popen("NAgent.exe")
            sys.exit(0)

        return 0
    except:
        print("[-] Failed to check for new update")

    if(jsonData != ""):
        print("[-] Could not read server response")
        return -1
    subprocess.Popen("NAgent.exe")


def downloadUpdate(URL, output):
    r = requests.get(URL)
    with open(output, 'wb') as f:
        f.write(r.content)

serverIP = "http://www.neehack.com/"
agentVersion()