# Tomcat完整检查表

来源: 01-报告模板\安全基线检查表\Tomcat完整检查表.xlsx

## 综合报告
1.基础信息
主机名称 | IP地址 | 所属业务系统
评估人员 | 联系 | 评估时间
客户人员 | 联系 | 质量评审时间
加固人员 | 联系 | 加固时间
2.评估结果综述
评估结果如下：
类别\发现的弱点 | I级风险 | II级风险 | III级风险 | IV级风险
Service Packs和Hotfixs安装情况 | #REF! | #REF! | #REF! | #REF!
审计和帐号策略 | #REF! | #REF! | #REF! | #REF!
安全设置 | #REF! | #REF! | #REF! | #REF!
注册表安全设置 | #REF! | #REF! | #REF! | #REF!
不必要的服务 | #REF! | #REF! | #REF! | #REF!
文件系统 | #REF! | #REF! | #REF! | #REF!
个人版防火墙和防病毒软件 | #REF! | #REF! | #REF! | #REF!
后门查找 | #REF! | #REF! | #REF! | #REF!
应用检查 | #REF! | #REF! | #REF! | #REF!
总计 | #REF! | #REF! | #REF! | #REF!
0.附注说明
A.范围及版本说明
　　本checklist适用于Windows2003系统的人工评估及加固。
版本：Ver 20080717
B.漏洞严重级别定义
等级 | 说明
I | 漏洞能够使攻击者直接获得系统控制权限，或者绕过防火墙。
II | 漏洞会泄露使攻击者获得系统访问权的信息。
III | 系统泄露的信息会使系统遭到攻击。
IV | 漏洞如果被修补，会提高系统的安全性。
C.漏洞严重级别定义
类别\弱点 | I级风险 | II级风险 | III级风险 | IV级风险
Service Packs和Hotfixs安装情况 | #REF! | #REF! | #REF! | #REF!
审计和帐号策略 | #REF! | #REF! | #REF! | #REF!
安全设置 | #REF! | #REF! | #REF! | #REF!
注册表安全设置 | #REF! | #REF! | #REF! | #REF!
不必要的服务 | #REF! | #REF! | #REF! | #REF!
文件系统 | #REF! | #REF! | #REF! | #REF!
个人版防火墙和防病毒软件 | #REF! | #REF! | #REF! | #REF!
后门查找 | #REF! | #REF! | #REF! | #REF!
应用检查 | #REF! | #REF! | #REF! | #REF!
总计 | #REF! | #REF! | #REF! | #REF!
## 评估报告
Tomcat中间件检查表
系统IP：
分类 | 检查选项 | 评估操作示例 | 符合情况 | 加固操作示例
身份鉴别 | TOMCAT Manager 密码是否已设置密码（非空或非用户名与密码一样） | Windows版本检查${CATALINA_HOME}/conf/tomcat-users.xml中，
<user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
linux版本中：cat tomcat/conf/tomcat-users.xml | 密码包含数字，字母，特殊字符三种形式，长度不小于8位
是否启用安全域验证（BASIC、DIGEST、FORM其中之一） | Windows版本：检查tomcat/conf/web.xml文件,auth-method方法为哪种
Linux版本中：cat CATALINA_HOME/conf/web.xml | grep auth-method查看 | 1、BASIC(基本验证)：通过HTTP验证，需要提供base64编码文本的用户口令
2、DIGEST(摘要验证)：通过HTTP验证，需要提供摘要编码字符串的用户口令
3、FORM(表单验证)：在网页的表单上要求提供密码
根据系统实际需求进行调整。
访问控制 | 是否指定TOMCAT Manager 管理IP地址 | Windows版本：检查${CATALINA_HOME}/conf/server.xml，Host name=“IP地址”
Linux版本：cat CATALINA_HOME/conf/server.xml | grep Hostname | 指定特定的IP地址作为Tomcat的登录地址
是否修改远程关闭服务器的命令 | Windows版本：检查tomcat/conf/server.xml中，shutdown=“字符串”
Linux版本中：cat CATALINA_HOME/conf/server.xml | grep shutdown | 将shutdown字符串设置得更复杂一些，避免过于简单轻易被人远程关闭
是否tomcat中禁止浏览目录下的文件, listings值为false | Windows版本中：检查/tomcat/conf/web.xml中， 
<param-name>listings</param-name>
 <param-value>false</param-value>
linux版本中：输入命令 cat tomcat/conf/ web.xml | grep listings | 将listings的值设为false
日志审计 | 是否启用日志功能 | Windows版本：检查tomcat/conf/server.xml，ctrl+F搜索logs字段，在<valve…….>中无“！”及开启了日志功能
linux版本中：cat $CATLINA_HOME/conf/server.xml | 一般默认设置如：                                                    <!--
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"  
               prefix="localhost_access_log." suffix=".txt" pattern="common" resolveHosts="false"/>
        -->
日志启用时应无<! --      --> 此两个标志符
日志是否启用详细记录选项，pattern值为各种% | Windows版本：检查tomcat/conf/server.xml中，pattern="%h %l %u %t"，每个字母代表记录访问源IP、本地服务器IP、记录日志服务器IP、访问方式、发送字节数、本地接收端口、访问URL地址等相关信息在日志文件中Linux版本中：cat $CATLINA_HOME/conf/server.xml | grep pattern | 标准默认的配置是这样：
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %u %t &quot;%r&quot; %s %b" />
我们根据实际的业务需求来指定日志记录的类型
安全防护 | 错误信息是否自定义 | 检查conf/web.xml，在最后</web-app>一行之前加入以下内容：
<error-page> 
<error-code>404</error-code>
<location>/noFile.htm</location> 
</error-page>
……………
<error-page>
<exception-type>java.lang.NullPointerException</exception-type>
<location>/error.jsp</location> 
</error-page>
 | 将错误信息页面转到自己自定义的界面中，防止信息泄露
在最后</web-app>一行之前加入以下内容：
<error-page> 
<error-code>404</error-code>
<location>/noFile.htm</location> 
</error-page>
……………
<error-page>
<exception-type>java.lang.NullPointerException</exception-type>
<location>/error.jsp</location> 
</error-page>
更改默认管理端口 | 检查conf/server.xml中，搜索"connection port"，默认是8080，要求修改为其他未占用的端口
linux版本中：cat tomcat/conf/server.xml |grep 'Connector port' | Windows版本：记事本代开server.xml，修改connection port端口号为其他端口，保存退出。
Linux版本：vim编辑server.xml，修改端口号，qw保存退出。
超时自动登出 | Windows版本：检查/tomcat/conf/server.xml，ConnectionTimeout字段的大小，默认是20000秒，要求修改为300秒
Linux版本：cat tomcat/conf/server.xml |grep connectionTimeout | Windows版本：记事本代开server.xml，修改ConnectionTimeout字段为300，保存退出。
Linux版本：vim编辑server.xml，修改ConnectionTimeout，qw保存退出。
剩余信息保护 | 是否禁止把session写入文件 | 检查conf/web.xml
    <Manager pathname="" />
取消注释：
 <!--  -->
默认：
 <!--  <Manager pathname="" />
--> | Windows版本：记事本打开web.xml，取消<!-- -->;
Linux版本：vim编辑web.xml，将<!-- -->删除了，qw保存退出
是否增强SessiionID的生成算法和长度，加密算法为SHA-512,长度为40 | 示例：
<Manager className="org.apache.catalina.session.StandardManager" algorithm="SHA-512" sessionIdLength="40">
         </Manager> | Windows版本：记事本打开web.xml，查找SHA字段，修改为SHA-512,Length长度为40；
Linux版本：vim编辑web.xml，按Windows修改，qw保存退出。
其他安全选项 | 使用https通讯加密 | Windows版本：使用https方式登录tomcat manager管理界面
Linux版本：cat tomcat/conf/server.xml |grep scheme=”https” secure=”true” | Windows版本：(1)使用JDK自带的keytool工具生成一个证书
$JAVA_HOME/bin/keytool  -genkey –alias tomcat –keyalg  RSA
-keystore-keystore /path/to/my/.keystore生成keystore；
.keystore 运行keystore；
(2)修改tomcat/conf/server.xml配置文件，更改为使用https方式，增加如下行：
<Connector classname="org.apache.catalina.http.HttpConnector"
 port="8443" minProcessors="5"  maxprocessors="100" enableLookups="true"
 acceptCount="10" debug="0" scheme="https" secure="true" 
clientAuth="false" keystoreFile="/path/to/my/.keystore"
keystorePass="runway" protocol="TLS"/>

是否删除不需要的管理应用和帮助应用。 | 根据实际需要删除
是否使用普通系统帐户启动TOMCAT. | 1、windows环境下打开程序-管理工具-服务-打开名称为APACHE TOMCAT 的服务选择-登录选项卡查看此帐户项为普通用户（非ADMINISTRATORS组用户和SYSTEM用户，通过检查管理员组确定该启动帐户非管理员帐户）。　　　　　　　　　　　　　　　　　　　　　　　　　２、ＵＮＩＸ（ＬＩＮＵＸ）使用ps -ef  命令检查TOMCAT的系统进程是否由非ROOT用户启动。 | 根据实际需要设置
## 安全加固报告
编号 | 分类 | 加固项 | 风险等级 | 需要加固 | 加固情况 | 加固操作示例
是否进行加固 | 加固内容 | 备注
#REF! | #REF! | #REF! | I | #REF! | 未处置
1.1 | #REF! | I | #REF! | 未处置
2.1 | TOMCAT Manager 密码是否已设置密码（非空或非用户名与密码一样） | II | #REF! | 未处置
2.1 | 是否指定TOMCAT Manager 管理IP地址 | II | #REF! | 未处置
2.1 | 是否tomcat中禁止浏览目录下的文件, listings值为false | II | #REF! | 未处置
2.1 | 是否启用日志功能 | III | #REF! | 未处置
2.1 | 日志是否启用详细记录选项，pattern值为各种% | II | #REF! | 未处置
2.1 | 错误信息是否自定义 | II | #REF! | 未处置
2.1 | 更改默认管理端口 | III | #REF! | 未处置
2.1 | 超时自动登出 | III | #REF! | 未处置
2.1 | 使用https通讯加密 | III | #REF! | 未处置
2.1 | 是否删除不需要的管理应用和帮助应用。 | IV | #REF! | 未处置
注：加固步骤请参考加固方案。
