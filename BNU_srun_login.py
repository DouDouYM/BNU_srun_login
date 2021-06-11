# -*- coding: utf-8 -*-
"""
Created on Mon Jun  7 12:44:56 2021

@author: YM
"""
import warnings
warnings.filterwarnings('ignore')
import requests
import re
import numpy as np
import socket
import os
import time
import math
import hmac
import hashlib
import getpass
import colorama
from colorama import Fore, Back, Style
colorama.init()
'''
登录脚本
'''

header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'}

init_url = 'http://172.16.202.204/'
get_challenge_api = "http://172.16.202.204/cgi-bin/get_challenge"
srun_portal_api = "http://172.16.202.204/cgi-bin/srun_portal"
srun_dm_api = "http://172.16.202.204/cgi-bin/rad_user_dm"
rad_user_info_api = "https://172.16.202.204/cgi-bin/rad_user_info"


n = '200'
type = '1'
ac_id = '1'
enc = "srun_bx1"


'''
加密算法
'''
'''
xencode
'''
def force(msg):
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)
def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0
def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd
def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)
def get_xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)

'''
base64
'''

_PADCHAR = "="
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
def _getbyte(s, i):
    x = ord(s[i]);
    if (x > 255):
        print("INVALID_CHARACTER_ERR: DOM Exception 5")
        exit(0)
    return x
def get_base64(s):
    i=0
    b10=0
    x = []
    imax = len(s) - len(s) % 3;
    if len(s) == 0:
        return s
    for i in range(0,imax,3):
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2);
        x.append(_ALPHA[(b10 >> 18)]);
        x.append(_ALPHA[((b10 >> 12) & 63)]);
        x.append(_ALPHA[((b10 >> 6) & 63)]);
        x.append(_ALPHA[(b10 & 63)])
    i=imax
    if len(s) - imax ==1:
        b10 = _getbyte(s, i) << 16;
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _PADCHAR + _PADCHAR);
    else:
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8);
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _ALPHA[((b10 >> 6) & 63)] + _PADCHAR);
    return "".join(x)

def get_md5(password,token):
	return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()






'''
连接校园网
'''


'''
随机生成jQuery参数
'''
def produce_jQuery():
    global jQuery
    strnum = ""
    for i in range(21):
        strnum = strnum+str(int(np.random.uniform(0, 9)))
    jQuery = "jQuery"+strnum+"_"



'''
获取当前ip，访问gw.bnu.edu.cn会提示连接不安全，但仍能获取ip
'''
def get_ip():
    global ip
    global callback
    callback = jQuery+str(int(time.time()*1000))
    init_res = requests.get('http://172.16.202.204/',
                            headers=header, verify=False)
    ip = re.search('id="user_ip" value="(.*?)"', init_res.text).group(1)


'''
获取token，访问get_challenge
'''
def get_token():
    global token
    get_challenge_params = {
        "callback": callback,
        "username": username,
        "ip": ip,
        "_": int(time.time()*1000),
    }
    get_challenge_res = requests.get(
        get_challenge_api, params=get_challenge_params, headers=header)
    token = re.search('"challenge":"(.*?)"', get_challenge_res.text).group(1)


'''
登录，重点在于构造请求参数[password,chksum,info]三个参数
'''

'''
加密生成[password,chksum,info]三个参数
'''
def data_encode():
    global i, hmd5, chkstr_final
    # 加密info
    info_temp = {"username": username,
                 "password": password,
                 "ip": ip,
                 "acid": ac_id,
                 "enc_ver": enc}
    i = re.sub("'", '"', str(info_temp))
    i = re.sub(" ", '', i)
    i = "{SRBX1}"+get_base64(get_xencode(i, token))
    # 加密password
    hmd5 = get_md5(password, token)
    # 加密info
    chkstr = token+username
    chkstr += token+hmd5
    chkstr += token+ac_id
    chkstr += token+ip
    chkstr += token+n
    chkstr += token+type
    chkstr += token+i
    chkstr_final = get_sha1(chkstr)


def login():
    produce_jQuery()
    get_ip()
    get_token()
    try:
        data_encode()
    except Exception:
        print(Fore.LIGHTRED_EX+"帐号密码错误！无法编码"+Style.RESET_ALL)
        return 1
    
    srun_portal_params = {
        'callback': callback,
        'action': 'login',
        'username': username,
        'password': '{MD5}'+hmd5,
        'ac_id': ac_id,
        'ip': ip,
        'chksum': chkstr_final,
        'info': i,
        'n': n,
        'type': type,
        'os': 'Windows+10',
        'name': 'Windows',
        'double_stack': '0',
        '_': int(time.time()*1000)
    }
    try:
        srun_portal_res = requests.get(
            srun_portal_api, params=srun_portal_params, headers=header)
        # 根据返回内容判断登录结果
        respond = eval(srun_portal_res.text[42:-1])
        error_msg = respond["error_msg"]
        if error_msg == "":
            print(Fore.LIGHTGREEN_EX+"登录成功！"+Fore.RESET)
            return 0
        elif error_msg == 'E2531: User not found.':
            print(Fore.LIGHTRED_EX+"登录失败！用户名错误"+Fore.RESET)
        elif error_msg == "E2553: Password is error.":
            print(Fore.LIGHTRED_EX+"登录失败！密码错误"+Fore.RESET)
        else:
            print(Fore.LIGHTRED_EX+"登录失败！错误码："+error_msg+Fore.RESET)
    except Exception:
            print(Fore.LIGHTRED_EX+"连接失败！请检查网络是否连通或配置错误"+Fore.RESET)
    return 1


#注销仅需要用户名和IP
def logout():
    if 'jQuery' not in vars():
        produce_jQuery()
        get_ip()
        
    t = int(time.time()*1000)
    srun_portal_params = {
    'callback': jQuery+str(t),
    'ip': ip,
    'username': username,
    'time': str(t),
    'unbind': '0',
    'sign': get_sha1(str(t) + username + ip + '0' + str(t))
    }
    try:
        srun_dm_res = requests.get(srun_dm_api,params=srun_portal_params,headers=header)
        respond = eval(srun_dm_res.text[42:-1])
        error_msg = respond["error"]
        if error_msg == "logout_ok":
            print(Fore.LIGHTGREEN_EX+"注销成功！"+Fore.RESET)
            return 0
        elif error_msg == "not_online_error":
            print(Fore.LIGHTRED_EX+"注销失败！您已经注销"+Fore.RESET)
        else:
            print(Fore.LIGHTRED_EX+"注销失败！错误码："+error_msg+Fore.RESET)
    except Exception:
        print(Fore.LIGHTRED_EX+"连接失败！请检查网络或配置错误"+Fore.RESET)
    return 1








'''
测试网络是否成功连接
'''
def isNetOK(testurl='www.baidu.com', port=443, trytimes=3, Maxtimeout=0.5):
    print("正在连接至："+testurl+"...")
    testserver = (testurl, port)
    isOK = []
    for i in range(trytimes):
        t0 = time.time()
        s = socket.socket()
        s.settimeout(Maxtimeout)
        try:
            status = s.connect_ex(testserver)
            t1 = time.time()
            if status == 0:
                print("成功！\t耗时："+str(round((t1-t0)*1000)) +
                          "ms\t"+str(status)+":"+os.strerror(status))
                isOK.append(True)
            else:
                print("失败！\t耗时："+str(round((t1-t0)*1000)) +
                      "ms\t"+str(status)+":"+os.strerror(status))
                isOK.append(False)
        except Exception:
            print("超时！"+Style.RESET_ALL)
            isOK.append(False)
        s.close()
    if sum(isOK):
        return True
    else:
        return False

def test_net_state():
    # 能否连接校园网
    lan_net_state = isNetOK('172.16.202.204', port=8082, trytimes=3)
    # 能否连接百度
    wlan_net_state = isNetOK(trytimes=3)
    # 能否连接外网
    # isNetOK('www.google.com')
    if(lan_net_state and wlan_net_state):
        print(Fore.LIGHTGREEN_EX+"您已成功连接至校园网！"+Fore.RESET)
    if(not wlan_net_state and lan_net_state):
        print(Fore.LIGHTRED_EX+"您尚未连接至校园网！请登录校园网帐号！"+Fore.RESET)
    if(not lan_net_state):
        print(Fore.LIGHTRED_EX+"您尚未连接至内网！请检查网络设备！"+Fore.RESET)


def get_user_info(verbose = True):
    global callback, username, ip, used_bytes
    produce_jQuery()
    t = int(time.time()*1000)
    callback = jQuery+str(t)
    get_user_params={"callback": callback, "_": t}
    
    try:
        get_user_res = requests.get(rad_user_info_api, 
                                    params=get_user_params, 
                                    headers=header, 
                                    timeout=1, 
                                    verify=False)
    except Exception:
         print(Fore.LIGHTRED_EX+"连接失败！网络断开，请检查网络"+Fore.RESET)
         return 1   
    respond = eval(get_user_res.text[42:-1])
    error_msg = respond["error"]
    if error_msg == "ok":
        username = respond["user_name"]
        ip = respond["online_ip"]
        #剩余流量
        remain_bytes = respond["remain_bytes"]
        #已用流量
        used_bytes = respond["sum_bytes"]
        if verbose:
            print(Fore.LIGHTGREEN_EX+"您已登录校园网！"+Fore.RESET,
                  "帐号："+username,
                  "IP："+ip,
                  "剩余流量："+str(round(remain_bytes/1024**3,2))+"GB",
                  "已用流量："+str(round(used_bytes/1024**3,2))+"GB",
                  sep = "  ")
        return 0
    elif error_msg == 'not_online_error':
        if verbose: 
            print(Fore.LIGHTRED_EX+"您尚未登录校园网！"+Fore.RESET)
        return 1
    else:
        if verbose: 
            print(Fore.LIGHTRED_EX+"您尚未登录校园网！"+error_msg+Fore.RESET)
        return 1
    
def test_url():
    try:
        url = input("请输入网址：")
        port = int(input("请输入端口号："))
        isNetOK(testurl=url, port=port)
    except Exception:
        print(Fore.LIGHTRED_EX+"输入错误！"+Fore.RESET)













'''
上次登录和新登录
'''
def recent_login():
    global username, password
    #上次成功登录的帐号密码保存在外部文件中
    try:  
        with open("setting.txt","r") as f:
            recent_username, recent_password = f.read().split()
    except Exception:
        print("本地没有保存帐号！")
        return 1
    while(1):
        recent_login_input = input("您想使用上次登录的帐号：{} 吗？[y/n]：".format(recent_username))
        if(recent_login_input == "Y" or recent_login_input == "y"):
            username = recent_username
            password = recent_password
            login_state = login()
            if(login_state == 1):
                if(input("按回车键重新输入...(输入\q返回上一层)")=="\\q"):
                    break
            if(login_state == 0):
                return 0
        elif(recent_login_input == "N" or recent_login_input == "n"):
            return 1
        else:
            print(Fore.LIGHTRED_EX+"输入错误！"+Fore.RESET)
            if(input("按回车键重新输入...(输入\q返回上一层)")=="\\q"):
                return 1

def new_login():
    global username, password
    print("使用新帐号登录：")
    while(1):
        username = input("请输入帐号：")
        if(len(username)<6): 
            print(Fore.LIGHTRED_EX+"输入帐号过短！"+Fore.RESET)
            continue
        password = getpass.getpass("请输入密码：")
        login_state = login()
        if(login_state == 1):
            if(input("按回车键重新输入...(输入\q返回上一层)")=="\\q"):
                break            
        if(login_state == 0):
            return 0
    return 1

def save_u_p():
     with open("setting.txt","w") as f:
        f.write(username+" "+password)


'''
主逻辑
'''
text = "\n0  登录校园网\n1  注销校园网\n2  检测网络环境\n3  测试指定网址及端口\n\q 退出脚本\n"
def main():
    #第一层
    while(1):
        print(Fore.LIGHTWHITE_EX + Back.BLUE)
        print("-----------欢迎使用！-----------\n")
        net_state = get_user_info()
        print(text+Style.RESET_ALL)
        main_input = input("请选择对应功能：")
        #功能0
        if (main_input == '0' and net_state == 0):
            print(Fore.LIGHTRED_EX+"请不要重复登录！"+Fore.RESET)
        elif(main_input == '0'):
            #第二层
            login_state = recent_login()
            if(login_state == 0):
                save_u_p()
            else:
                login_state = new_login()
                if(login_state == 0):
                    save_u_p()
                else:
                    print("\n\n")
                    continue

        #功能1
        elif (main_input == '1' and net_state == 1):
            print(Fore.LIGHTRED_EX+"请不要重复注销！"+Fore.RESET)
        elif (main_input == '1'):
            get_user_info(verbose=False)
            logout()
            
        
        #功能2
        elif (main_input == '2'):
            get_user_info(verbose=False)
            test_net_state()
            
            
        #功能3
        elif (main_input == '3'):
            test_url()

        elif (main_input == '\\q'):
            print("退出！")
            break
        else:
            print(Fore.LIGHTRED_EX+"输入错误！"+Fore.RESET)
            
        input("按回车键重新输入...")
        print("\n\n")




if __name__ == '__main__':
    main()






