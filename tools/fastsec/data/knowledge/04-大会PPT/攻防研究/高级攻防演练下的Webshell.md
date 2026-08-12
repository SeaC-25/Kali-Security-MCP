# 高级攻防演练下的Webshell

来源: 04-大会PPT\攻防研究\高级攻防演练下的Webshell.pdf

高级攻防下的WEBSHELL

About Me
0 1
• 张一臣BeichenDream;
• 360政企安全-高级攻防实验室-安全研究资深工程师
• JVM安全研究者
• 哥斯拉作者

目录
CONTENTS
0 1
01
PART 01
流量对抗
02
PART 02
武器化
03
PART 03
内存马
05
PART 05
Agent对抗
06
PART 06
正向代理
07
PART 07
哥斯拉插件扩展
04
PART 04
Java反射绕过

PART.01 
0 2
对抗流量审查
• 伪装正常业务的流量

为什么要对抗流量审查
0 1
蚁剑
• 防止流量被他人窃取分析
• 不想被人发现异常流量
• 防止被WAF拦截
冰蝎
哥斯拉
三大常用webshell默认流量

将哥斯拉流量扩展成Html之扩展请求包
0 1
不支持扩展的shell不是好shell
扩展时尽量模仿正常业务请求流量
扩展时尽量模仿正常业务返回流量
模仿某搜索引擎流量
1. 截取任意post表单请求数据
2. 选取rsv_t参数作为密码
3. 重新生成一个shell 密码为rsv_t的参数
4. 设置请求追加数据

将哥斯拉流量扩展成Html之扩展返回包
0 1
不支持扩展的shell不是好shell
扩展时尽量模仿正常业务请求流量
扩展时尽量模仿正常业务返回流量
模仿某搜索引擎流量
5. 截取任意页面将shell放入任何位置

将哥斯拉流量扩展成Html之查看扩展成果
0 1
不支持扩展的shell不是好shell
扩展时尽量模仿正常业务请求流量
扩展时尽量模仿正常业务返回流量
模仿某搜索引擎流量
6. 查看成果它就像是正常的业务流量一样且可以被渲染

将哥斯拉流量扩展成Json之扩展请求包
0 1
不支持扩展的shell不是好shell
扩展时尽量模仿正常业务请求流量
扩展时尽量模仿正常业务返回流量
模仿正常业务Json流量
1. 截取任意json请求数据
2. 生成一个默认的shell
3. 选取数据出现位置这里选择encrypt参数尾部
4. 设置请求追加数据

将哥斯拉流量扩展成Json之扩展返回包
0 1
不支持扩展的shell不是好shell
扩展时尽量模仿正常业务请求流量
扩展时尽量模仿正常业务返回流量
5.  手动解析encrypt值分离出哥斯拉流量
6.  将Payload的返回值赋值给result->user
7.  将result对象作为json输出
模仿正常业务Json流量

将哥斯拉流量扩展成json之查看扩展成果
0 1
不支持扩展的shell不是好shell
扩展时尽量模仿正常业务请求流量
扩展时尽量模仿正常业务返回流量
9. 查看成果它就像是正常的业务流量一样且可以被解析
模仿正常业务Json流量

哥斯拉流量扩展之查看扩展成果
0 1
不支持扩展的shell不是好shell
扩展时尽量模仿正常业务请求流量
扩展时尽量模仿正常业务返回流量

PART.02 
0 2
将Webshell武器化
• Pty
• 内存加载
• 后渗透

全交互的Pty shell
0 1
• Linux下采用python pty模块
• Windows 采用Winpty & shellhost
• 客户端使用jediterm解析Pty数据流

内置多个权限提升模块
0 1
• BadPotato
• SweetPotato
• EfsPotato
• 由于IIS是服务权限拥有模拟Token权限所以提权利用使用稳定性比较高的Potato
• 权限提升后哥斯拉会保存高权限token以供后利用做准备
• 权限提升后可直接以高权限账户运行Mimikatz
• 这全过程都是在内存中运行的没有任何文件落地
• 内存运行技术采用pe_to_shellcode

在内存中运行任意可执行程序
0 1
• 可自定义程序参数
• 支持x86/x64可执行程序
• 可自定义远程进程/pid

提权后一键运行Mimikatz
0 1
• 提权后可一键抓取系统密码
• 提权后可以以高权限执行shellcode
• 直接以高权限用户上线msf/cs

PART.03 
0 2
内存马
• asp.net(iis)   虚拟目录与MVC内存马
• Java Agent 通用内存马
• 在仅执行命令情况下获得内存马

asp.net(iis)  内存马
0 1
• 为了获得更完整的控制功能
• 不会在磁盘残留文件
• 可绕过静态查杀

asp.net(iis)  虚拟目录内存马
0 1
• asp.net在每个请求到达Page Resource时会执行
HostingEnvironment.VirtualPathProvider.GetCacheKey获取缓存Key

asp.net(iis)  虚拟目录内存马
0 1
• 所以我们可以把HostingEnvironment.VirtualPathProvider
替换成我们自己的实现类这样每次执行请求都会触发我们的恶意类

asp.net MVC内存马
0 1
• 刚刚我们讲到了虚拟目录内存马而在MVC中如果控制器拦截了所有的请求
就无法触发GetCacheKey方法
• 在.NET3.5以后新增System.Web.Routing.RouteTable.Routes类
里面存放了MVC所有的路由数据每次请求过来会触发GetRouteData方法我们
可以把我们的路由插到第一位在GetRouteData做请求处理

Java通用agent内存马
0 1
• 总所周知Java Agent内存马与操作系统有关
• 在不同JDK中tools库也不同
• 在JDK9以后把库统一并内置在了JDK
• JDK9以后无法注入agent到自身进程

统一jdk tools GodzillaAgent
0 1
重写Java tools库
native函数未链接时会抛出异常
利用这个特性可以遍历所有Machine获取到正确的Machine

编写通用内存马
0 1
• 大多数Java web容器都是使用的标准servlet-api实现
• servlet-api 有Servlet,Filter, Listener 三大应用组件
• 理论上来说要实现通用的内存马,我们要Hook所有的Servlet,Filter
• 在Tomcat,Weblogic,Jboos,WebSphere,Jetty经过测试完美运行
• 正常访问页面就是正常页面

仅命令执行获取内存马
0 1
1. 从外网下载Godzilla Agent Jar包
2. 找到文件上传把Godzilla Agent传上去
3. 使用bash命令分块写入Godzilla Agent Jar包

PART.04 
0 2
Java反射防御机制绕过
• bypass jdk16 security module 
• bypass jdk reflection Filter

绕过Java16新增的模块保护
0 1
• Java16 新增模块保护功能模块中的类只有在module-info显式导出时才能被其
他模块访问导致大量不安全的类无法访问
• 不同的模块不能使用反射访问其私有字段以及私有方法导致我们在jdk16之后
漏洞后利用开发受到大量限制比如tomcat回显会反射Thread私有字段在jdk16之
后无法再反射其私有字段

绕过Java16新增的模块保护
0 1
bypass jdk16 security module
先获取被反射类的Class模块然后通过Unsafe.objectFieldOffset
获取Class模块在内存的偏移地址
然后使用Unsafe.getAndSetObject方法将当前类的Class模块替
换成被反射类的Class模块这样就可以反射其模块下所有类
的私有字段以及方法了

绕过Java Reflection Filter
0 1
• Jdk 12-17 禁用了多个类成员字段导致我们在编写
漏洞Exp以及后利用时受到限制
jdk.internal.reflect.Reflection

绕过Java Reflection Filter
0 1
由于受到Reflection Filter的限制
我们无法使用反射置空methodFilterMap和fieldFilterMap成员
但是我们可以获取到其class字节码定义一个匿名类
然后获取其字段在内存的偏移
然后使用unsafe Api置空methodFilterMap和fieldFilterMap成员

PART.05 
0 2
Agent对抗
• 通过JNI绕过Rasp
• 通过Class重加载绕过Rasp

通过JNI绕过Rasp
0 1
• 自写JNI native绕过PASS需要适配系统
• 通过Web容器内置native函数绕过
YES
• 和Rasp说拜拜

Class重载绕过Rasp之从java虚拟机获得jvmti对象
0 1
获得jvmti对象
Jvm抛出没有能力重定义类
给Jvmti手动加上权能

Class重载绕过Rasp之定位JNI地址
0 1
1. 解析/proc/self/maps获得so内存偏移地址与路径
2. Elf导出函数相对地址+so内存偏移=绝对地址
3. 用函数绝对地址替换我们之前的硬编码地址

Class重载绕过Rasp之cpp转与位置无关的shellcode
0 1
• 不能使用函数可以用内联函数替代需要开启编译优化
• 关闭所有安全检查
• 使用基于堆栈的字符串
• x32需要关闭pic
找到函数起始地址把函数复制出来

Class重载绕过Rasp之cpp转与位置无关的shellcode
0 1
1. 解析o文件定位函数偏移
2. 解析o文件获取函数大小
3. 把我们编写的函数复制出来

0 1
Class重载绕过Rasp之patchVM
• 右图是JVM回调Java层Agent的流程图
• native层收到重载类消息后会调用所有Agent的eventHandlerClassFileLoadHook事件
• eventHandlerClassFileLoadHook事件会通过getJPLISEnvironment获取JPLISEnvironment上下文
• JAVA层的Agent会自动在native层注册eventHandlerClassFileLoadHook事件到ClassFileLoadHook
• 如果environment不为NULL 则调用Java层的transform方法通知Agent Hook该类
• Java类的加载或类重载JVM都会调用eventHandlerClassFileLoadHook事件
• getJPLISEnvironment调用jvmtienv->GetEnvironmentLocalStorage 获取存储的JPLISEnvironment上下文

0 1
Class重载绕过Rasp之patchVM
• 在我们UnHook之前我们需要把已有的Agent给“杀掉”
1. Hook Java层InstrumentationImpl 不够Hack
3. Hook Native函数Cool
2. Hook Java层TransformerManager 不够Hack
• 在Java层做UnHook容易被Agent拦截

0 1
Class重载绕过Rasp之patchVM
我们如果Hook Java层的函数很有可能被之前的Agent给拦掉
所以我们直接选择Hook Native层函数
在上面我们已经得知调用GetEnvironmentLocalStorage方法如果返回错误environment上下文会为NULL
environment为NULL就不会调用Java层的transform方法
所以我们直接Hook GetEnvironmentLocalStorage 让它直接返回错误

Class重载绕过Rasp之编写native函数
0 1
1. 查找回调类定位回调方法
2. 遍历所有已经加载到JVM的类
3. 调用回调方法进行类的修改

Class重载绕过Rasp之编写Java回调函数
0 1
以UnHook 命令执行为例我们从Jar包读取原始的类替换掉被Hook的类
从视频可以看到我们成功通过重载绕过OpenRasp

0 1

Class重载绕过Rasp
0 1
• 支持绝大部分JDK  在以下Java发行版经过测试
• patchVM执行后其它Agent再也无法注入当前JVM虚拟机
• 可以绕过国内外几乎所有公开的Rasp以及国内厂商自研Rasp
• 不仅可以绕过Rasp还可以注入通用内存马
Java发行版
版本范围
Support Bypass Agent
OpenJDK
6+
支持
OracleJDK
6+
支持
ZuluJDK
6+
支持
jrockit
6+
支持
SapMachine
6+
支持
Microsoft
6+
支持
Kona JDK
6+
支持
LibericaJDK
6+
支持
毕昇JDK
6+
支持

PART.06 
0 2
不出网获得稳定代理
• 通过Http Chunk获得稳定隧道代理
• 通过哥斯拉获得稳定隧道代理

Http chunk正向代理
0 1
分块传输编码（Chunked transfer encoding）是超
文本传输协议（HTTP）中的一种数据传输机制，
允许HTTP由应用服务器发送给客户端应用（通常
是网页浏览器）的数据可以分成多个部分

Http chunk正向代理
0 1
优点：
1.  长连接不会中断
2.  仅需要发送一个Http请求
3.  速度很快
4.  可以在任何系统运行
缺点：
1.  不支持反向代理

Http chunk正向代理
0 1
Http Chunk优点很多缺点很少于是我开发了Chunk-Proxy

0 1
Chunk-proxy对各个Web容器的支持
容器
语言
是否支持双向流
是否支持长时间连接
Chunk-proxy是否支持
Tomcat
Java
双向流
支持长连接
支持
Weblogic
Java
双向流
支持长连接
支持
Jboos
Java
双向流
支持长连接
支持
Resin
Java
双向流
支持长连接
支持
Jetty
Java
双向流
支持长连接
支持
websphere
Java
双向流
支持长连接
支持
glassfish
Java
双向流
支持长连接
支持
IIS
C#
单向流
支持长链接
支持

哥斯拉正向代理
0 1
• I/O多路复用多个Socket共用一个隧道
• 数据传输协议基于二进制结构
• 传输流量加密错误重试重试校验
• 支持Socks代理和端口映射以及转发
• 支持负载均衡

不出网上线C2
0 1

PART.07 
0 2
开发后渗透插件
• 通过哥斯拉Api 快速编写编写内存加载Mimikatz插件

编写哥斯拉插件
0 1
新建一个项目并把哥斯拉添加到依赖库

编写哥斯拉插件
0 1
1. 新建包包名必须以shells.plugins.作者名
2. 新建一个Swing Panel

编写哥斯拉插件
0 1
使用IDEA拖拽图形化界面

编写哥斯拉插件
0 1
1. 使用PluginAnnotation注解
2. 实现Plugin接口
3. 保存插件初始化时传入的上下文
4. 将Mimikatz复制到包目录下

编写哥斯拉插件
0 1
1. 为runButton添加单击事件
2. 通过getPlugin获取ShellcodeLoader插件
3. 读入Mimikatz到内存
4. 调用ShellcodeLoader在内存中加载PE
5. 将输出展示到resultTextArea

编写哥斯拉插件
0 1
1. 添加导出jar
2. 在导出中删除godzilla依赖

编写哥斯拉插件
0 1
在配置->插件配置导入我们编写的插件

编写哥斯拉插件
0 1
插件KconMimikatz成功被加载
点击Run按钮成功在内存运行Mimikatz

疑问与交流
哥斯拉下载连接：https://github.com/BeichenDream/Godzilla
Rasp对抗代码：https://github.com/BeichenDream/Kcon2021Code
JDK对抗代码：https://github.com/BeichenDream/Kcon2021Code
Chunk-Proxy ：https://github.com/BeichenDream/Chunk-Proxy
GenericAgentTools ：https://github.com/BeichenDream/GenericAgentTools
通用Java内存马：https://github.com/BeichenDream/GodzillaWebAgent

M        A        N        O        E        U        V        R        E
感谢观看！
KCon 汇聚黑客的智慧
