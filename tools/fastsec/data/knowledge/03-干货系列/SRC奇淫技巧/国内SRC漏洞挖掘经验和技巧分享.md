# 国内SRC漏洞挖掘经验和技巧分享

来源: 03-干货系列\SRC奇淫技巧\国内SRC漏洞挖掘经验和技巧分享.pdf

国内SRC漏洞挖掘经验和技巧分享

ID: PwnDog\硬糖_zzz
唐朝| 成都体育学院体育新闻专业
前PKAV团队成员
研究方向: Web安全以及......
关于我

1.SRC个人推荐
2.SRC的规则
3.漏洞挖掘中的个人经验和技巧分享
目录

同程网易360 唯品会腾讯阿里巴巴
京东小米陌陌滴滴
百度蚂蚁金服
SRC个人推荐
备注:排名不分先后，只为排版好看

白帽子
1.合规手段
2.点到为止
3.漏洞保密
SRC的规则

信息收集
1.厂商域名
2.厂商IP段
3.厂商业务信息

域名收集
1. 基于SSL证书查询
2. 第三方网站接口查询
3. Github
4. DNS解析记录
5. 子域名枚举等等

域名收集
基于SSL证书查询
1.censys.io
2.crt.sh
第三方接口查询网站
1. riskiq
2. shodan
3. findsubdomains
4. censys.io
5. dnsdb.io

案例

案例

案例

案例

案例

案例

IP段收集
ipwhois.cnnic.net.cn

IP段收集

IP段收集
ipwhois.cnnic.net.cn

IP段收集

端口扫描
Python+Masscan+Nmap

端口扫描
遇到防火墙时

端口扫描

端口扫描

端口扫描
Nmap参数
-sV
//识别服务
-sT
//只需普通用户权限
-Pn
//跳过主机发现过程
--version-all  //全部报文测试
--open  //只探测开放端口

字典的收集与使用优化
字典的获取
用之于民，取之于民

字典获取
域名类字典
https://opendata.rapid7.com/sonar.rdns_v2/
https://opendata.rapid7.com/sonar.fdns_v2/
300G   脏数据剔除体力活

站点类字典
1.目录类2.可执行脚本类3.参数类4.静态资源类(js)
字典获取

站点类字典
1000+ Code AND Regex!
字典获取

字典获取

字典获取

字典获取

案例
Uber 某站二次注入
JS泄露API+API爆破+参数爆破=二次注入

案例

案例

案例

案例
403 or 404？
此地无银三百两!

案例

案例

案例
http://106.**.**.147/adver/landing.php?mac=1

字典的使用优化
量大
关键词入库
增加计数int字段
扫描器命中时增加计数
下次提取字典时降序提取

业务安全
业务是核心,但也有薄弱点
1.非普通用户拥有的权限，如：商家，合作方
2.新上线业务

APP测试
SSL Pining
越狱ios禁止SSL Pinning抓App Store的包
ios: http://pwn.dog/index.php/ios/ios-disable-ssl-pinning.html
瘦蛟舞——安卓证书锁定解除的工具
Android: https://github.com/WooyunDota/DroidSSLUnpinning

END
谢谢大家！
