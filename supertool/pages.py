import re
import json
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64decode,b64encode
import urllib
from functions import checkheader, encodepass

# login
def login(r,host,user,password):
    a = r.get("http://{}/?_type=loginData&_tag=login_entry".format(host))
    resp = json.loads(a.text)
    sess_token = resp['sess_token']
    a = r.get("http://{}/?_type=loginData&_tag=login_token".format(host))
    s = a.text
    x = re.search(r'>(.*?)<',s).group(1)
    pass1 = password+x
    shapass = sha256(pass1.encode()).hexdigest()
    a = r.post("http://{}/?_type=loginData&_tag=login_entry".format(host), 
        data = {
            'action':'login',
            'Password':shapass,
            'Username':user,
            '_sessionTOKEN':sess_token
        }
    )  
    print("[Login]: {}".format(a.text))


# lan status
def lanstatus(r):
    a = r.get("http://192.168.0.1/?_type=menuView&_tag=localNetStatus&Menu3Location=0")
    a = r.get("http://192.168.0.1/?_type=menuData&_tag=status_lan_info_lua.lua")
    print(a.text)

def samba_get(r,host):
    a = r.get("http://{}/?_type=menuView&_tag=samba&Menu3Location=0".format(host))
    btoken = re.search(r'_sessionTmpToken = "(.*?)";',a.text).group(1)
    token = bytes.fromhex(btoken.replace('\\x','')).decode()
    a = r.get("http://{}/?_type=menuData&_tag=Samba_lua.lua".format(host))
    return(token)

def samba_post(r, host, sess_token, status, user, passwd):
    token = sess_token
    encode, passb64 = encodepass(passwd)
    post_data = {
        "IF_ACTION":"Apply",
        "_InstID":"IGD",
        "_InstNum":"1",
        "EnableSmb":status,
        "AutoRun":"0",
        "SambaSwitch":"2",
        "NetbiosName":"smbshare",
        "AuthType":"1",
        "_InstID_0":"IGD.SAMBAUSER0",
        "UserName_0":user,
        "PassWord_0":passb64,
        "_InstID":"IGD",
        "UserName":"",
        "PassWord":passb64,
        "Btn_cancel_Samba":"",
        "Btn_apply_Samba":"",
        "encode":encode,
        "_sessionTOKEN":token
    }
    form = urllib.parse.urlencode(post_data)
    checkb64 = checkheader(form)
    a = r.post("http://{}/?_type=menuData&_tag=Samba_lua.lua".format(host),
        data = post_data,
        headers = {
            "Check":checkb64
        }
    )
    print("[Samba_post]: Setting samba status {} (0=off, 1=on)".format(status))


def ping_get(r):
    a = r.get("http://192.168.0.1/?_type=menuView&_tag=networkDiag&Menu3Location=0")
    btoken = re.search(r'_sessionTmpToken = "(.*?)";',a.text).group(1)
    token = bytes.fromhex(btoken.replace('\\x','')).decode()
    a = r.get("http://192.168.0.1/?_type=menuData&_tag=networkdiag_ping_lua.lua")
    print(a.text)
    print(token)
    return(token)

def ping_post(r,sess_token):
    token = sess_token
    post_data = {
        "IF_ACTION":"PingDiagnosis",
        "_InstID":"",
        "Host":"130.206.1.3",
        "Interface":"",
        "NumofRepeat":"4",
        "DataBlockSize":"56",
        "Timeout":"2000",
        "Btn_cancel_PingDiagnosis":"",
        "Btn_PingDiagnosis":"",
        "PingAck":"",
        "_sessionTOKEN":token
    }
    form = urllib.parse.urlencode(post_data)
    checkb64 = checkheader(form)
    a = r.post("http://192.168.0.1/?_type=menuData&_tag=networkdiag_ping_lua.lua",
        data = post_data,
        headers = {
            "Check":checkb64
        }
    )
    print(a.text)

def traceroute_get(r):
    a = r.get("http://192.168.0.1/?_type=menuView&_tag=networkDiag&Menu3Location=0")
    btoken = re.search(r'_sessionTmpToken = "(.*?)";',a.text).group(1)
    token = bytes.fromhex(btoken.replace('\\x','')).decode()
    a = r.get("http://192.168.0.1/?_type=menuData&_tag=networkdiag_traceroute_lua.lua")
    token = bytes.fromhex(btoken.replace('\\x','')).decode()
    print(a.text)
    print(token)
    return(token)

def traceroute_post(r,sess_token):
    token = sess_token
    post_data = {
        "IF_ACTION":"TraceRouteDiagnosis",
        "_InstID":"",
        "Control":"0",
        "Host":"130.206.1.3",
        "Interface":"",
        "MaxHopCount":"30",
        "Timeout":"5000",
        "Protocol":"UDP",
        "Btn_TraceRouteDiagnosis":"",
        "Result":"",
        "_sessionTOKEN":token
    }
    form = urllib.parse.urlencode(post_data)
    print(form)
    checkb64 = checkheader(form)
    a = r.post("http://192.168.0.1/?_type=menuData&_tag=networkdiag_traceroute_lua.lua",
        data = post_data,
        headers = {
            "Check":checkb64
        }
    )
    print(a.text)

def download_get(r,host):
    a = r.get("http://{}/?_type=menuView&_tag=usrCfgMgr&Menu3Location=0".format(host))
    btoken = re.search(r'_sessionTmpToken = "(.*?)";',a.text).group(1)
    token = bytes.fromhex(btoken.replace('\\x','')).decode()
    a = r.get("http://{}/?_type=menuData&_tag=updownload_prevent_ctl.lua&sessToken={}".format(host,token))
    #token = bytes.fromhex(btoken.replace('\\x','')).decode()
    print("[Download-get]: Registering token {}".format(token))
    return(token)

def download_post(r,host,sess_token):
    token = sess_token
    post_data = {
        "config":"",
        "TOKEN_DOWNLOAD":token
    }
    a = r.post("http://{}/?_type=menuData&_tag=do_download_usercfg.lua".format(host),
        files = post_data
    )
    print("[Download-post]: Received size {} bytes".format(len(a.content)))
    print("[Download-post]: Writing to file config.bin...")
    f = open("config.bin", "wb")
    f.write(a.content)
    f.close()

def macforkey_get(r,host):
    a = r.get("http://{}/?_type=menuView&_tag=ethWanStatus&Menu3Location=0".format(host))
    a = r.get("http://{}/?_type=menuData&_tag=wan_internetstatus_lua.lua&TypeUplink=2&pageType=1".format(host))
    x = re.search(r'WorkIFMac</ParaName><ParaValue>(.*?)</ParaValue>',a.text).group(1)
    return(x)

def serialforkey_get(r,host):
    #a = r.get("http://{}/?_type=menuView&_tag=statusMgr&Menu3Location=0".format(host))
    #a = r.get("http://{}/?_type=menuData&_tag=devmgr_statusmgr_lua.lua".format(host))
    #To be removed if new solution is consistent
    a = r.get("http://{}/?_type=menuView&_tag=ponSn&Menu3Location=0".format(host))
    a = r.get("http://{}/?_type=menuData&_tag=poninfo_sn_lua.lua".format(host))
    x = re.search(r'Sn</ParaName><ParaValue>(.*?)</ParaValue>',a.text).group(1)
    return(x)


