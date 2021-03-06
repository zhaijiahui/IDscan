# IDscan V3.0



https://github.com/zhaijiahui/IDscan

check Information_Disclosure

用于检查敏感信息泄露

Welcome all friends to mention more suggestions for improvement

欢迎各位朋友多提改进意见



## Environment

python 3.x

pip install requests threadpool



## Catalog

- IDscan
	- get_ip_list.py
		- Used to traverse the IP segment|用于遍历IP段
	- IDscan.py
		- threadpool
		- random User-Agent
	- rules.txt
		- leak rules
	- url_list.txt
		- Fill in the detected content |将被检测内容填入其中
	- README.md
	



## url_list.txt Example

**if you scan network segment|如果你想扫描网段**

```
192.168.0.0-192.168.0.255
192.167.36.24-192.168.39.255
```

**if you want to scan special port | 如果你想扫描特殊端口**

``` 192.168.0.1:8081```

**if you wang to scan website url| 如果你想扫描网站地址**

```
http://www.baidu.com
https://www.baidu.com
http://www.baidu.com:81
```




## Support



| Type             | Explanation        | Exp                                      |
| ---------------- | ------------------ | ---------------------------------------- |
| /.svn/entries| SVN信息泄露       | Seay-Svn源代码泄露漏洞利用工具   |
| /.git/config | Git信息泄露       | https://github.com/BugScanTeam/GitHack |
| /.DS_Store | DS_Store文件泄露   | https://github.com/lijiejie/ds_store_exp |
| /.hg/ | .hg源码泄漏 | https://github.com/kost/dvcs-ripper/blob/master/rip-hg.pl |
| /.bzr/|.bzr信息泄露|https://github.com/kost/dvcs-ripper/blob/master/rip-bzr.pl|
| /.bzr/|.bzr信息泄露|https://github.com/kost/dvcs-ripper/blob/master/rip-bzr.pl|
| /CVS/Entries|cvs信息泄露|https://github.com/kost/dvcs-ripper/blob/master/rip-cvs.pl|
| /WEB-INF/web.xml | 初始化工程配置信息泄露 |   |
| /crossdomin.xml  | 跨域策略文件       |     |
| /icons/          | 目录遍历路径       |       |
| /robots.txt      | 爬虫配置文件           |                    |
| /uddiexplorer/SearchPublicRegistries.jsp|Weblogic 服务器请求伪造漏洞||
| /ws_utc/config.do|Oracle WebLogic ws-utc 任意文件上传漏洞||
| :8080/manage\|/:8080/script | Jenkins未授权访问可执行命令 | |
| :9200/_cat/indices\|:9200/\_river/_search | Elasticsearch未授权访问 | |
| :5984/_config/ | CouchDB未授权访问 | |
| :2375/containers/json | Docker未授权访问 | |
|:8161/admin/\|ActiveMQ未授权访问|||
|/test.cgi\|/test.php\|/info.php|测试页面||
|/login.php\|/admin.php\|/manager.php\|/admin_login.php|管理后台地址泄露||
|/.test.php.swp\|/test.php.bak\|/test.jsp.old\|/cgi~|编辑器备份文件泄露||
|/phpmyadmin|phpmyadmin后台泄露||
|/phpinfo.php|phpinfo页面泄露||
|/basic/index.php|HTTP认证泄露漏洞||
|/www.rar\|/web.zip\|/sitename.tar.gz|网站备份文件||
|/_vti_inf.html|Frontpage 信息泄漏||
|/_vti_pvt/service.pwd|FrontPage pwd 文件可读||
|/.bashrc|bashrc 信息泄漏||
|/.bash_profile|profile 信息泄露||
|/.zshrc|zsh 信息泄露||
| ...              | ...                |     |



## BUG

\# v2.1

+ 修复读取文件编码错误
+ 修复批量读取文件问题
+ 添加的网站存在斜杠去除
+ 添加weblogic两个未授权访问

\# v2.3

+ 添加多个信息泄露问题，并精简代码

\# v3.0

+ 修改了严重bug
+ 添加多个信息泄露问题，并精简代码




## Gratitude

- JingYi