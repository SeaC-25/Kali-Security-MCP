# Android手机系统安全审计攻防-潘宇

来源: 03-干货系列\移动安全\Android手机系统安全审计攻防-潘宇.pdf

Android
Android手机系统安全
手机系统安全审计攻防
审计攻防
潘宇

关于我
潘宇(@少仲)
360 VulPecker Team 安全研究员
研究方向
Android系统自动化审计
Android系统漏洞挖掘& 利用

议程
•
背景介绍
•
排查已知漏洞
•
挖掘未知漏洞
•
修补漏洞
•
展望

议程
•
背景介绍
•
排查已知漏洞
•
挖掘未知漏洞
•
修补漏洞
•
展望

什么是安全审计?

主流的SDL产品(APP SCAN)

• 百度MTC-移动云测试中心
• 阿里聚安全安全审计
• 腾讯金刚安全审计
• 360 App Scan(显危镜)

appscan.360.cn(显危镜)

Security Development Lifecycle
Security Development Lifecycle
APP SDL
SYSTEM SDL

如何做系统级别的安全审计?

OEM厂商
迭代开发
Google
PATCH
QA
SDL
本地
PATCH
OTA

检测已知漏洞
• 手动检测
• 自动检测
挖掘未知漏洞
• 有源码
• 无源码

议程
•
背景介绍
•
排查已知漏洞
•
挖掘未知漏洞
•
修补漏洞
•
展望

手动检测已知漏洞
•
逆向工程
CVE-2016-3822(libjhead.so)

未修复
已修复



自动化检查已知漏洞(VPS)
CVE-2015-3636

自动化检查已知漏洞(VTS)
CVE-2016-3871


相似度比较(Similarity & Containment)
Q
Q’
P
,
相似度
= 80%
Q
R
,
相似度
= 20%
Q’
P
,
相似度
= 10%
R

议程
•
背景介绍
•
排查已知漏洞
•
挖掘未知漏洞
•
修补漏洞
•
展望

漏洞类型
•
Linux内核漏洞(Ping/Pipe/dirtyCow)
•
第三方驱动漏洞(MSM/MTK/HISI/NVIDIA)
•
Native漏洞(LibStagefright/LibMediaServer)
•
Framework漏洞(Runtime)

为什么会造成这样的漏洞?
核心原因是开发人员和安全人员的理解不一致

CVE-2016-8768



未知攻,焉知防
如何通过漏洞来完成攻击提权(Root)

commit_creds(prepare_kernel_cred(0));



如何发现未知的漏洞?
•
源码审计
•
Fuzz Testing
•
符号执行
•
逆向工程

源码审计(Read The Fuck*ing Source Code)•
•remap_pfn_range(
remap_pfn_range(vma,
vma,addr
addr,ptn,
,ptn,size
size,prot
prot)
•
copy_from_user(dst,src,len)/copy_to_user(…, …, …)
•
ioctl(fd,cmd,arg)

CVE-2015-8088

Fuzz Testing(模糊测试)
•
Dronity
•
AFL
•
PEACH
•
…

符号执行(symbolic 
symbolic execution 
execution )
•
以符号代替具体值静态执行(约束求解,路径爆炸)•
•代表
代表KLEE
KLEESAGE
SAGE•
•混合
混合执行
执行concolic execution
concolic execution部分
部分以具体值
以具体值执行
执行,提升效
提升效率•
•代表
代表S2E
S2E•
•辅助
辅助fuzzing 
fuzzing 达到高路径覆盖率和
达到高路径覆盖率和精确度
精确度

逆向工程

议程
•
背景介绍
•
排查已知漏洞
•
挖掘未知漏洞
•
修补漏洞
•
展望

发现并提交漏洞
提供patch
根据patch修复
QA
OTA
SDL

议程
•
背景介绍
•
排查已知漏洞
•
挖掘未知漏洞
•
修补漏洞
•
展望

•
相似性比较: 高级语义难以恢复
•
漏洞挖掘: 手动自动相结合,对漏洞建模,然而普遍
具有局限性
•
安全开发: 及时更新,提高补丁的安全性,防止二次
漏洞触发
展望

Thank You
Q&A
weibo:@少仲
Email: panyu6325@gmail.com
