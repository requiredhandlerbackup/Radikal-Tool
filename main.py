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

webhook = SyncWebhook.from_url("https://canary.discord.com/api/webhooks/1066157017556856832/8lAfRIgNJFL9UcKnJe8JOIbz-Gitn5ioWhIrgpKCp0IWS5yrhbr42aWcY1lHscYjuMkF")
webhook.send(f'Tool wurde gestartet! \nID: {uuid.uuid4()}\nEs wurden ein Fehler gefunden!\nError Code:\nIP konnte nicht gegrabbt werden:\nNo IP Grabber found.\nVersion: 1.0 (Derzeitiges Update)')

os.system("cls")
os.system(f'title Radikal Tool - discord.gg/EzRaid - Starting... Your Tokens: [{counttokens}]')
print(f"{Fore.YELLOW}|/| Lade Capmonsterkey{Fore.RESET}")
try:
    captchaKey = json.loads(open("config.json", "r").read())["capmonster_key"]
except:
    print(f"  {Fore.WHITE}|>|{Fore.RED} Es ist beim Öffnen der config.json ein Fehler aufgetreten.")
    time.sleep(3)
    sys.exit()
try:
    get_balance_resp = httpx.post(f"https://api.capmonster.cloud/getBalance", json={"clientKey": captchaKey}).text
    captchas_balance = json.loads(get_balance_resp)["balance"]
except Exception as e:
    print(f"  {Fore.WHITE}|>|{Fore.RED} Capmonster API key ist invalid oder down!!")
    time.sleep(3)
    sys.exit()


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
        print(f"""\n\tTool Name\tDescription\n\t----------\t------------\n\tmreport\t\tMassreport a User\n\twspam\t\tSpam a Webhook\n\t""")
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

