# -*- coding=utf-8 -*-

# Author:Zhaijiahui
# description: Small vulnerability scanner AND No interaction vulnerability type for attack and page
# date: 2019/1/4
# https://github.com/zhaijiahui/collect_self_script/tree/master/Information_Disclosure

import requests
import re,os,sys,time,random
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

def httpd(u,j,w,way):
    r = requests.get(way + ip + u,headers=headers,timeout=3,verify=False) # http
    html = r.text
    if r.status_code == 200:
        if j in html:
            print('Find: ' + way +ip + u +' is Leak !!! Leak is '+ w)
        else:
            print('Find: ' + way +ip + u +' is Exist !!!')

def verify(ip):
    headers_list = [
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0',
    'Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X) AppleWebKit/602.4.6 (KHTML, like Gecko) Version/10.0 Mobile/14D27 Safari/602.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X; zh-CN) AppleWebKit/537.51.1 (KHTML, like Gecko) Mobile/14D27 UCBrowser/11.6.1.1003 Mobile  AliApp(TUnionSDK/0.1.20)',
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3",
    "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24",
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24"
    ]
    headers = { 'User-Agent': random.choice(headers_list) }
    f = open('rules.txt','r',encoding='utf-8')
    txt = f.readlines()
    for x in txt:
        u,j,w = x.split('|')
        try:
            httpd(ip,u,j,w,way='http://')
        except Exception as e:
            try:
                httpd(ip,u,j,w,way='https://')
            except Exception as e:
                pass
    

def main():
    print('*'*35+'''\nIDscan V2.2 By Zhaijiahui\n
Information disclosure Check.\n'''+'*'*35)
    with open('url_list.txt','r',encoding='utf-8') as f:
        url_l = f.readlines()
    pool = threadpool.ThreadPool(255)
    ipl = []
    for i in url_l:
        if 'http' in i: # website url
            temp = i.split('://')
            url_temp = temp[1].strip('/')
            ipl.append(url_temp.strip())
        elif '-' in i: # network segment
            start_ip,end_ip = i.split('-')
            ipl.extend(get_ip_list.iplist(start_ip,end_ip))
        elif checkip(i):
            ipl.append(i.strip())
        else:
            print('Unknown form IP：'+i)
    print('Start...')
    # print(ipl)
    requests = threadpool.makeRequests(verify, ipl)
    [pool.putRequest(req) for req in requests]
    pool.wait()

    print('End...')



if __name__ == '__main__':
    main()