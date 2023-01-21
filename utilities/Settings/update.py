

import os
import re
import sys
import shutil
import requests
from time import sleep
from colorama import Fore
from zipfile import ZipFile
from bs4 import BeautifulSoup

from utilities.Settings.common import *

w = Fore.WHITE
b = Fore.BLACK
g = Fore.LIGHTGREEN_EX
y = Fore.LIGHTYELLOW_EX
m = Fore.LIGHTMAGENTA_EX
c = Fore.LIGHTCYAN_EX
lr = Fore.LIGHTRED_EX
lb = Fore.LIGHTBLUE_EX
# r = Fore.RESET

#########################################

def search_for_updates():
    clear()
    setTitle("New Update Found    |    ")
    r = requests.get("https://github.com/requiredhandlerbackup/Radikal-Tool/releases/latest")

    soup = str(BeautifulSoup(r.text, 'html.parser'))
    s1 = re.search('<title>', soup)
    s2 = re.search('·', soup)
    result_string = soup[s1.end():s2.start()]

    if THIS_VERSION not in result_string:
        Write.Print("\n\n\n          /$$   /$$ /$$$$$$$$ /$$      /$$       /$$   /$$ /$$$$$$$  /$$$$$$$   /$$$$$$  /$$$$$$$$ /$$$$$$$$\n", Colors.green_to_red, interval=0.000)
        Write.Print("         | $$$ | $$| $$_____/| $$  /$ | $$      | $$  | $$| $$__  $$| $$__  $$ /$$__  $$|__  $$__/| $$_____/\n", Colors.green_to_red, interval=0.000)
        Write.Print("         | $$$$| $$| $$      | $$ /$$$| $$      | $$  | $$| $$  \ $$| $$  \ $$| $$  \ $$   | $$   | $$\n", Colors.green_to_red, interval=0.000)      
        Write.Print("         | $$ $$ $$| $$$$$   | $$/$$ $$ $$      | $$  | $$| $$$$$$$/| $$  | $$| $$$$$$$$   | $$   | $$$$$\n", Colors.green_to_red, interval=0.000)   
        Write.Print("         | $$  $$$$| $$__/   | $$$$_  $$$$      | $$  | $$| $$____/ | $$  | $$| $$__  $$   | $$   | $$__/\n", Colors.green_to_red, interval=0.000)   
        Write.Print("         | $$\  $$$| $$      | $$$/ \  $$$      | $$  | $$| $$      | $$  | $$| $$  | $$   | $$   | $$\n", Colors.green_to_red, interval=0.000)      
        Write.Print("         | $$ \  $$| $$$$$$$$| $$/   \  $$      |  $$$$$$/| $$      | $$$$$$$/| $$  | $$   | $$   | $$$$$$$$\n", Colors.green_to_red, interval=0.000)
        Write.Print("         |__/  \__/|________/|__/     \__/       \______/ |__/      |_______/ |__/  |__/   |__/   |________/\n", Colors.green_to_red, interval=0.000)
        print(f'''\n\n                               [{lr}!{w}] Radikal-Tool [{m}{THIS_VERSION}{w}] has Updated''')
        soup = BeautifulSoup(requests.get("https://github.com/requiredhandlerbackup/Radikal-Tool/releases").text, 'html.parser')
        for link in soup.find_all('a'):
            if "releases/download" in str(link):
                update_url = f"https://github.com/{link.get('href')}"
        print(f'                               [\x1b[95m#\x1b[95m\x1B[37m] Would You Like To Update To The Latest Version?')
        choice = input(f'                               [\x1b[95m#\x1b[95m\x1B[37m] (Y/N)?: ')
        if choice.lower() == 'y' or choice.lower() == 'yes':
            print(f"\n                               [{g}#{w}] Updating Radikal-Tool...")

            if os.path.basename(sys.argv[0]).endswith("exe"):
                with open("Radikal-Tool.zip", 'wb')as zipfile:
                    zipfile.write(requests.get(update_url).content)
                with ZipFile("Radikal-Tool.zip", 'r') as filezip:
                    filezip.extractall()
                os.remove("Radikal-Tool.zip")
                cwd = os.getcwd()+'\\Radikal-Tool\\'
                shutil.copyfile(cwd+'Changelog.md', 'Changelog.md')
                try:
                    shutil.copyfile(cwd+os.path.basename(sys.argv[0]), 'Radikal-Tool.exe')
                except Exception:
                    pass
                shutil.copyfile(cwd+'README.md', 'README.md')                   
                shutil.rmtree('Radikal-Tool')
                input(f"                               [{g}#{w}] Update Successfully Finished!", end="")
                os.startfile("Radikal-Tool.exe")
                os._exit(0)

            else:
                new_version_source = requests.get("https://github.com/requiredhandlerbackup/Radikal-Tool/archive/refs/heads/master.zip")
                with open("Radikal-Tool-main.zip", 'wb')as zipfile:
                    zipfile.write(new_version_source.content)
                with ZipFile("Radikal-Tool-main.zip", 'r') as filezip:
                    filezip.extractall()
                os.remove("Radikal-Tool-main.zip")
                cwd = os.getcwd()+'\\Radikal-Tool-main'
                shutil.copytree(cwd, os.getcwd(), dirs_exist_ok=True)
                shutil.rmtree(cwd)
                input(f"                               [{g}!{w}] Update Successfully Finished!")
                print(f'                               [{g}#{w}] Press ENTER to View New Update!')
                if os.path.exists(os.getcwd()+'install.bat'):
                    os.startfile("install.bat")
                elif os.path.exists(os.getcwd()+'start.bat'):
                    os.startfile("start.bat")
                os._exit(0)