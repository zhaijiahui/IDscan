# -*- coding=utf-8 -*-
# Author:Zhaijiahui
# https://github.com/zhaijiahui/collect_self_script/tree/master/Information_Disclosure

import requests
import re,os,sys,time
import random
import threadpool
import get_ip_list

from requests.packages.urllib3.exceptions import InsecureRequestWarning,InsecurePlatformWarning   # 屏蔽错误提示的一般方法，配合下面两个disable
import requests.packages.urllib3.util.ssl_                   # 解决部分ssl证书版本不正确的问题
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'

requests.packages.urllib3.disable_warnings(InsecureRequestWarning) # 移除ssl错误告警
requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)

def checkip(ip): # match ip
    p = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)')
    if p.match(ip):
        return True
    else:
        return False

def request(ip):
    headers_list = ['Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0',
'Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16',
'Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X) AppleWebKit/602.4.6 (KHTML, like Gecko) Version/10.0 Mobile/14D27 Safari/602.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X; zh-CN) AppleWebKit/537.51.1 (KHTML, like Gecko) Mobile/14D27 UCBrowser/11.6.1.1003 Mobile  AliApp(TUnionSDK/0.1.20)']
    headers = { 'User-Agent': headers_list[random.randint(0,4)] }
    f = open('rules.txt','r')
    txt = f.readlines()
    for x in txt:
        u,j,w = x.split('|')
        try:
            r = requests.get('http://'+ ip + u,headers=headers,timeout=3,verify=False)
            html = r.text
            if r.status_code == 200:
                if j in html:
                    print('Find: ' + 'http://'+ip + u +' is Leak !!! Leak is '+ w)
                else:
                    print('Find: ' + 'http://'+ip + u +' is Exist !!!')
        except Exception as e:
            try:
                r = requests.get('https://'+ ip + u,headers=headers,timeout=3,verify=False)
                html = r.text
                if r.status_code == 200:
                    if j in html:
                        print('Find: ' + 'https://'+ip + u +' is Leak !!! Leak is '+ w)
                    else:
                        print('Find: ' + 'https://'+ip + u +' is Exist !!!')
            except Exception as e:
                pass
    

def main():
    print('*'*35+'''\nIDscan V1.0 By Zhaijiahui\n
Information disclosure Check.\n'''+'*'*35)
    with open('url_list.txt','r') as f:
        url_list = f.readlines()
    pool = threadpool.ThreadPool(255)
    ipl = []
    for i in url_list:
        if 'http' in i: # website url
            temp = i.split('://')
            ipl.append(temp[1].strip())
        elif '-' in i: # network segment
            start_ip,end_ip = i.split('-')
            ipl = get_ip_list.iplist(start_ip,end_ip)
        elif checkip(i):
            ipl.append(i.strip())
        else:
            print('Unknown form IP：'+i)
    # print(ipl)
    print('Start...')
    requests = threadpool.makeRequests(request, ipl)
    [pool.putRequest(req) for req in requests]
    pool.wait()

    print('End...')



if __name__ == '__main__':
    main()