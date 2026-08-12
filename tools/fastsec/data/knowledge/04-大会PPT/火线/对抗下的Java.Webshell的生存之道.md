# 对抗下的Java.Webshell的生存之道

来源: 04-大会PPT\火线\对抗下的Java.Webshell的生存之道.pptx

"快手内部文档请勿外传"
「观火」安全技术沙龙
X
对抗下的Java Webshell的生存之道
快手安全高级工程师：林茂新
——————————

自我介绍 
林茂新（l1nk3r）
练习时长两年半的代码审计工程师
现快手安全高级工程师
Xray team && 90sec team 核心成员

目录
1、Java Webshell的静态对抗
2、Java Webshell层面的动态对抗
3、Java Webshell的一些小Trick

1、Java Webshell的静态对抗

Webshell的静态对抗
为什么Webshell会被D盾等静态查杀攻击检查出来？
1、普通命令执行马
2、Webshell连接工具服务端Shell文件（例如：冰蝎、哥斯拉）

Webshell的静态对抗
核心检查方式，正则关键字扫描

解决思路：
- 尽量避免出现关键字，例如:exec、system、execute、shell、cmd等。
- 由于判断系统操作类型`System.getProperty/getProperties`带有一些关键字，可以考虑使用fileSeparator进行代替。
- 使用Scanner代替常见的BufferedReader方法接受回显。

Webshell的静态对抗

Webshell的静态对抗

Webshell的静态对抗


2、Java Webshell层面的动态对抗

Java Webshell层面的动态对抗
1、WAF的流量拦截 
2、WAF的语义引擎
3、RASP

流量层面-冰蝎3
Content-Type: application/octet-stream
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

流量层面-哥斯拉

流量层面-哥斯拉-Base64
第一个包：User-agent为jdk版本号，请求内容长度较大，参数为单个参数，首次请求会有Set-Cookie操作。

流量层面-哥斯拉-Base64
第二个包：User-agent为jdk版本号，Cookie在第二行，请求内容长度较小，参数为单个参数，响应包长度固定为56个字节，响应内容字符特征固定：38个数字字母==16个数字字母。

流量层面-哥斯拉-RAW
第一个包：User-agent为jdk版本号，请求长度的、固定，请求内容为二进制数据，响应包存在Set-Cookie操作。

流量层面-哥斯拉-RAW
第二个包：User-agent为jdk版本号，Cookie在第二行，请求内容长度固定32个字符，内容为二进制数据，响应包长度固定为16个字节。

流量层面-内存马
在请求图片文件的情况下，返回的响应类型Content-Type通常也是text/html

语义WAF
这是一个命令执行shell，对于AST的语义waf，他的输出可控，他的输出是命令执行，所以被拦截。

语义WAF

语义WAF
\u000d实际上是一个换行符/r，Java会解析Unicode编码，在执行阶段把它当作是一个换行符，所以实际上执行效果就是如下所示。

语义WAF
对于语言特性的差异导致绕过，在语义WAF非常常见
原因在于我们通过新的
RASP
RASP的核心思路还是根据调用栈来拦截webshell
原因在于我们通过新的线程启动一个Context中没有url，所以绕过了

RASP
通过JNI的接口方式直接逃离命令执行检查的HOOK点也是一种绕过方式

RASP
把恶意代码放到异常当中执行。

3、Java Webshell的一些小Trick

Trick
反弹Shell的时候不要用命令进行反弹，会触发EDR等安全设备告警，可采用Java API

Trick
利用sun.misc.BASE64Encoder的兼容性来混淆base64编码
    public static void main(String args[]) throws IOException {
        String test = "YWFhYQ===";
        byte[] encrypted = new BASE64Decoder().decodeBuffer(test);
        byte[] decrypted = Base64.getDecoder().decode(test);
    }

Trick
sun.misc.BASE64Decoder这个方法做base64解码的时候，针对base64的兼容性更高，你在base64的字符串后面无论加多少个=都没关系，但是在例如java.util.base64.decode这类型严格按照base64规范的进行解码的方法下，就会出现报错。

职位描述
1、产品安全测试，安全评估，以及代码审计；
2、跟踪安全动态，研究前沿安全技术，对互联网重大安全漏洞进行响应分析；
3、对网络入侵，业务风险事件进行响应处理。

任职要求
1、良好的计算机基础，熟悉操作系统，网络基础原理，熟悉TCP/IP、HTTP等协议；
2、熟练使用sqlmap、burpsuite、metasploit等常见安全测试工具，了解原理，熟悉代码并且对其进行过二次开发者优先；
3、熟悉java代码审计；
4、良好的编码能力。熟练使用Python，Shell，Lua; 熟悉mysql、redis等；
5、具有良好的沟通协调能力、较强的团队合作精神、优秀的执行能力；
6、有很强的分析问题和解决问题的能力。
优先条件
1、在各大SRC、乌云、freebuf等平台上发表或报告有独到见解、技术创新、思路创新的漏洞或文章；
2、熟悉移动app安全，理解app安全需求；熟悉app安全问题处理、预防的手段和方法；能够独立进行安卓、iOS平台的app逆向和安全测试；
3、精通某一安全的细分领域技术，如：代码审计、HIDS/WAF/扫描器等的规则编写、逆向技术、社会工程学、大数据情报分析等。
THANK YOU!
