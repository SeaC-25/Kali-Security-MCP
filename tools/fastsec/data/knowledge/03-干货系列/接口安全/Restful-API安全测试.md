# Restful-API安全测试

来源: 03-干货系列\接口安全\Restful-API安全测试.pdf

REST API安全测试的思路
基于Swagger的REST API自动化安
全测试实践
贾玉彬Gary
Gary_jia@rapid7.com

大纲
• 由应用安全说起
• 传统REST API安全测试
• 基于Swagger的REST API 的安全测试

在SDLC中尽早发现和修复安全问题
30X
15X
10X
5X
2X
Cost
Source:  NIST
Production
System  
testing
Integration/ component 
testing
Coding
Requirements

不同的团队不同的目标

DevSecOps
Image : Pete Cheslock at #DevOpsDaysAustin.
“Everyone is responsible for security” with the 
goal of safely distributing security decisions at 
speed and scale
It does not have to be like this:

传统的REST API安全测试

REST API
• REST – REpresentational State Transfer
• REST描述的是客户端和服务端的一种交互
形式，REST本身不实用，实用的是如何设
计RESTful风格API
• 传输资源的形式一般是JSON和XML

RESTful结构的好处
RESTful通过一套统一的接
口为Web, iOS和Android提
供服务
*图片来自互联网

REST API安全问题会带来的后果
• 接口被滥用消耗系统资源
• 数据泄露
• 伪造/篡改数据
• 应用被仿制
• 引入其他安全问题

REST API是可被攻击的
• REST API是可以被常用的攻击方法进行攻击
的，如注入、XSS、CSRF、XML Entity攻击等
等

REST API测试
• 通常没有WEB界面与之进行交互，通过HTTP的各种终端工
具或自己编写HTTP客户端脚本与服务端通讯来进行测试
• 通过变化API调用参数组合，变化API功能调用顺序，实现
全面和各种复杂组合的调用
• 针对安全测试也存在同样的问题

以移动应用为例的测试过程（手工）
• 安装配置代理
• 配置测试移动设备
• 准备测试用数据
• 手工测试

安装并设置代理、配置移动设备

手工测试REST API（SQL注入为例）
•
测试是否存在注入漏洞
•
例如使用PUT方法更新用户档案
•
请求中包含参数值（first_name)
URL: http://192.168.202.131/api/user/1
Method: PUT
Parameter name: first_name
Attack values: test’’

手工测试REST API（SQL注入为例）
Request 1
使用test’’把两个单引号（’）注入
到请求

手工测试REST API（SQL注入为例）
Response 1
用户档案成功提交

手工测试REST API（XSS为例）
•
测试是否存在XSS漏洞
•
例如使用PUT方法更新用户档案
•
请求中包含参数值（first_name)
URL: http://192.168.202.131/api/user/1
Method: PUT
Parameter name: first_name
Attack values: <script>alert(1)</script>

手工测试REST API（XSS为例）
Request
在请求中使用
<script>alert(1)<script>把一
个脚本标签注入到first_name
参数值

手工测试REST API（XSS为例）

使用DAST工具测试REST API
• 手工测试REST API是个很具挑战性的工作
• 大部分的DAST工具都需要training mode对
REST API进行测试（使用复杂的JSON、XML、
GWT结构）
• 方法：导入预先录制的流量文件进行测试

以AppSpider + BurpSuite为例
• BurpSuite使用广泛
• AppSpider可以接受各种录制的流量并且可
以识别JSON、XML、GWT、AMF参数和值，
不需要使用training mode

DEMO

基于SWAGGER的REST API的安全测试

基于Swagger的REST API
• Swagger是一个简单又强大的REST API文档
生成工具
• 标准的、语言无关的，通过它计算机和人
类无需阅读代码、文档或者监测网络流量
就能发现并理解Web服务

Swagger REST API

DEMO

运行AppSpider并选择Swagger Utility

导入Swagger JSON文件

API function calls

操作API参数

创建新的扫描配置



总结
• REST API安全测试很重要
• 尽量使用自动化/半自动化工具进行测试
• 使用Swagger生成REST API文档
• 使用支持Swagger的DAST进行安全测试

谢谢
