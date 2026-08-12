# Oracle完整检查表

来源: 01-报告模板\安全基线检查表\Oracle完整检查表.xlsx

## Sheet1
Oracle标准检查表
分类 | 测评项 | 预期结果 | 评估操作示例 | 检查情况 | 结果 | 整改建议
身份鉴别 | 应对登录操作系统和数据库系统的用户进行身份标识和鉴别 | 不存在默认空口令和默认口令的用户 | select username "User(s) with Default Password!"
from dba_users
where ACCOUNT_STATUS='OPEN' AND password in
根据反馈的结果对比默认口令的值可知是否存在默认口令
常见默认口令值：('E066D214D5421CCC', -- dbsnmp
'24ABAB8B06281B4C', -- ctxsys
'72979A94BAD2AF80', -- mdsys
'C252E8FA117AF049', -- odm
'A7A32CD03D3CE8D5', -- odm_mtr
'88A2B2C183431F00', -- ordplugins
'7EFA02EC7EA6B86F', -- ordsys
'4A3BA55E08595C81', -- outln
'F894844C34402B67', -- scott
'3F9FBD883D787341', -- wk_proxy
'79DF7A1BD138CF11', -- wk_sys
'7C9BA362F8314299', -- wmsys
'88D8364765FCE6AF', -- xdb
'F9DA8977092B7B81', -- tracesvr
'9300C0977D7DC75E', -- oas_public
'A97282CE3D94E29E', -- websys
'AC9700FD3F1410EB', -- lbacsys
'E7B5D92911C831E1', -- rman
'AC98877DE1297365', -- perfstat
'66F4EF5650C20355', -- exfsys
'84B8CBCA4D477FA3', -- si_informtn_schema
'D4C5016086B2DC6A', -- sys
'D4DF7931AB130E37') -- system;
 | 每个数据库用户都需要用户名和密码登录，对默认的数据库名不能使用默认的密码，必须修改为新的密码
数据库系统管理用户身份标识应具有不易被冒用的特点，口令应有复杂度要求并定期更换 | 数据库管理员口令最小长度为10，并包含数字、字母（大小写）、特殊字符这三种形式，账户口令的生存期不超过90天 | select * from dba_profiles order by profile;
PASSWORD_LIFE_TIME 90（生存期）PASSWORD_VERIFY_FUNCTION 10（口令长度）
PASSWORD_REUSE_MAX 5（最近5次重复密码不能使用）
FAILED_LOGIN_ATTEMPTS 6（失败次数超过6次锁定）
 | 管理员账户口令最小长度为10位，包含数字、字母、特殊字符三种形式，口令最长生存期为90天
应启用登录失败处理功能，可采取结束会话、限制非法登录次数等措施 | 设置非法登录次数的限制值，对超过限制值的登录终止其鉴别会话戒临时封闭帐号
 | 查看最大非法登录次数：
select limit from dba_profiles where profile='DEFAULT' and resource_name='FAILED_LOGIN_ATTEMPTS'
查看封闭账号策略：
select limit from dba_profiles where profile='DEFAULT' and resource_name='PASSWORD_LOCK_TIME'  | 最大非法登录次数为5次，账号封锁策略为登录失败5次后封锁5-10分钟
限制具备数据库超级管理员（SYSDBA）权限的用户远程管理登录 | SYSDBA用户只能本地登录不能远程，REMOTE_LOGIN_PASSWORDFILE函数的Value值为NONE | Show parameter REMOTE_LOGIN_PASSWORDFILE | REMOTE_LOGIN_PASSWORDFILE函数值设置未NONE，SQL>alter system set remote_login_passwordfile=none scope=spfile；
这样SYSDBA用户只能在本地登录，不能远程连接，再重启数据库完成
应采用两种或两种以上组合的鉴别技术对管理用户进行身份鉴别 | 对管理员访谈，对于三级系统，必须使用两种或两种以上组合的鉴别技术实现用户身份鉴别，如密码和口令的组合使用。 | 访谈管理员 | 三级系统建议采用用户名密码+证书口令登录的方式；
三级以下系统可以采用一种鉴别技术。
访问控制 | 应启用访问控制功能，依据安全策略控制用户对资源的访问 | 
明确了各账户的访问权限 | 根据实际需求，对每个用户的访问权限进行限制，对敏感的文件夹限制访问用户的权限
应根据管理用户的角色分配权限，实现管理用户的权限分离，仅授予管理用户所需的最小权限； | 每个登录用户的角色和权限是该用户所需的最小权限 | 访谈管理员，了解每个用户的作用、权限 | 给予账户所需最小权限，避免出现特权用户
应实现操作系统和数据库系统特权用户的权限分离 | 操作系统和数据库的特权用户的权限必须分离，避免一些特权用户拥有过大的权限，减少人为误操作 | 询问管理员，操作系统管理员和数据库管理员是否分离 | 分离数据库和操作系统的特权用户，不能使一个用户权限过大
应严格限制默认帐户的访问权限，重命名系统默认帐户，修改这些帐户的默认口令 | 不能以默认的账号和密码登录数据库 | 常见的Oracle数据库名和密码：sys/change_on_install
system/manager
oracle/oracle、admin、ora92
sys/oracle、admin | 对默认的账号和密码进行修改，避免存在弱口令
应及时删除多余的、过期的账户，避免共享账户存在 | 不存在多余、过期和共享账户 | select name from syslogins
询问每个账户的作用 | 删除多余、过期无用的账户
安全审计 | 审计范围应覆盖到服务器和重要客户端上的每个操作系统用户和数据库用户 | 系统开启了安全审计功能并覆盖到每个用户 | select value from v$parameter where name=„audit_trail‟ | 开启系统本身的安全审计功能，完整记录用户对操作系统和文件访问情况，或采用第三方的安全审计设备
审计内容应包括重要用户行为、系统资源的异常使用和重要系统命令的使用等系统内重要的安全相关事件
 | 审计功能已开启，包括：用户登录系统、自主访问控制的所有操作记录、重要用户行为（如增加/删除用户，删除库表）等进行审计 | show parmeter audit_trail，查看是否开启审计功能。
show parameter audit_sys_operations，查看是否对所有sys用户的操作迚行了记录。
select sel,upd,del,ins from dba_obj_audit_opts，查看是否对sel,upd,del,ins操作进行了审计。
select * from dba_stmt_audit_opts，查看审计是否设置成功。
select * from dba_priv_audit_opts，查看权限审计选项。 | 开启审计功能，记录用户的添加和删除、审计功能的启动和关闭、审计策略的调整、权限变更、系统资源的异常使用、重要的系统操作（如用户登录、退出）等操作
审计记录应包括事件的日期、触发事件的主体与客体、事件类型、事件成功或失败、身份鉴别事件中的请求来源 | 审计记录信息中应包括日期、时间、事件类型、主体标识（如用户名等）、客体标识（如数据库表、字段戒记录等）和事件操作结果等内容 | Select * from  DBA_AUDIT_TRAIL;
 | 完善审计记录，对事件的日期，事件的主客体，事件是否成功发生等进行完善
操作系统应遵循最小安装的原则，仅安装需要的组件和应用程序，并通过设置升级服务器等方式保持系统补丁及时得到更新 | 1)系统安装的组件和应用程序遵循了最小安装的原则；
2)不必要的服务没有启动；
3)不必要的端口没有打开；
 | service --status-all | grep running | 在不影响系统的正常使用的前提下，对系统的一些端口和服务可以进行关闭，避免这些端口或服务的问题导致系统问题
资源控制 | 应通过设定终端接入方式、网络地址范围等条件限制终端登录 | 已设定终端登录安全策略及措施，非授权终端无法登录管理 | /etc/hosts.deny、/etc/hosts.allow中对终端登录限制的相关配置参数 | 建议配置固定的终端、特定的网络范围内才能进行终端登录
应根据安全策略设置登录终端的操作超时锁定 | 已在/etc/profile中为TMOUT设置了合理的操作超时时间 | cat /etc/profile | 建议设置超时时间为300秒
