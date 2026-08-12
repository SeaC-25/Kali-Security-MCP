# MySQL完整检查表

来源: 01-报告模板\安全基线检查表\MySQL完整检查表.xlsx

## Sheet1
MySQL标准检查表
分类 | 测评项 | 预期结果 | 评估操作示例 | 检查情况 | 结果 | 整改建议
身份鉴别 | 默认账号要求 | 不存在默认数据库和默认帐号；
不存在匿名账户；
应用系统应使用新建用户，不得使用系统默认账户。
 | mysql> show databases;
mysql> select * from user;
只保留单个管理员root和应用系统专用账户 | 在不影响系统正常运行的情况下删除默认账号，若默认账号下有系统运行，则修改默认账号名。
数据库系统管理用户账号名和密码要求项 | 修改root用户默认口令，删除空口令；
改变默认mysql管理员帐号，host为空

 | mysql> select * from user;
查看列表中root用户口令不为空，host为空 | 修改root用户的默认密码，不能有空口令，MySQL默认的账户为root，需要新建一个账户。MySQL账户的Host=%应该为空，这样来禁止远程连接。
管理员口令策略 | 至少8位，数字、字母（大小写）、特殊字符组成的不规律密码 | mysql>select password from user;
查看密码 | 密码修改为8位以上，包含数字，字母（大小写），特殊字符三种形式
账号权限策略 | 除管理员账户之外的其他账户不得拥有系统数据库的任何权限，不得拥有File，Grant，Reload，Shutdown，Process等权限的任意一种 | mysql>show grants for root@localhost；查看root用户的权限。
Show grants for+用户名@地址，可以查看指定账户的权限 | 修改除管理员外其他用户的权限，其他用户不能有File，Grant，Reload，Shutdown，Process等权限，不能出现其他高权限用户
访问控制 | MySQL运行在单独的组上 | 不能在root账户运行MySQL服务器，使用普通非特权用户运行 | mysql>id mysql | MySQL不能运行在root用户上，需新建一个专用账户给MySQL数据库
文件权限控制 | MySQL的数据目录、日志目录，以及目录下的文件属主和属组只能是mysql账号，不能给予其他账号任何权限 | ls –la /usr/local/mysql；查看数据目录所属的账号
ls –la /usr/local/mysql/var
查看日志目录所属的账号

命令历史记录保护 | mysql.history文件中为空，没有命令历史记录 | 若没有修改存储历史命令的文件名，则是mysql.history，我们执行find / -name mysql.history站到文件夹所在的位置；
cat 打开查看该文件内容
若修改了存储的文件名，则需要询问管理员确认存储位置。 | 将.bash_history，.mysql_history文件置空。
ln -s /dev/null .bash_history；
ln -s /dev/null .mysql_history；
将历史命令缓存直接引向垃圾箱

安全审计 | 启用日志记录 | 启用了日志记录，记录日志信息
log-error,log,log-slow-queries这三种日志的状态是ON状态 | MySQL>show variables like 'log_%'; | 进入my.cnf中，在[mysqld]下面加log-error=/usr/local/mysql/log/error.log
log=/usr/local/mysql/log/mysql.log
long_query_time=2
log-slow-queries= /usr/local/mysql/log/slowquery.log
log-queries-not-using-indexes


审计记录应包括事件的日期、时间、类型、主体标识、客体标识和结果等 | 审计记录包括事件的日期、时间、类型、主体标识、客体标识和结果等内容 | cat /etc/audit/auditd.conf
cat /etc/audit/audit.rules
 | 首先需要开启logbin日志（记录数据库修改语句和生效时间），再与init-connect相结合，两者结合记录完整的信息
操作系统应遵循最小安装的原则，仅安装需要的组件和应用程序，并通过设置升级服务器等方式保持系统补丁及时得到更新 | 1)系统安装的组件和应用程序遵循了最小安装的原则；
2)不必要的服务没有启动；
 | service --status-all | grep running | 对不必要的服务进行关闭，仅保留系统所需要的最小服务
其他内容 | 限制单个用户允许的连接数量 | 对单个用户的连接数的最大值做出限制，my.cnf中的max_user_connections系统变量为非零值 | MySQL>show global variables like '%connect%' | 根据系统的实际承受能力，限制单个用户连接数，在/etc/my.cnf中进行限制
服务监听端口 | 修改mysql默认监听端口3306为其他端口 | show global variables like 'port';看一下监听端口是不是3306 | vim my.cnf文件，修改其中的port参数为非3306且未被占用的端口
登录终端超时锁定 | 设置了超时时间，在时间内没有操作，再次操作时就会提示超时 | MYSQL>show VARIABLES like '%timeout%';
或访谈了解防火墙等其他安全设备是否做了相关策略 | 设置interactive_timeout为300秒.
Mysql> set global interactive_timeout=300;
