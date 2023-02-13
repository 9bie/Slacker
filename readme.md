# Slacker
懒鬼插件

懒懒懒懒懒，我凭本事打下来的SESSION，为什么还要自己动手去后渗透？

从各种地方搜集来的奇怪的插件

自己审计了一番，确保没有后门，源码都放在dev目录下

不保证免杀，敏感操作请事先在本地测试

用，都tmd给我用，这样被溯源的时候就不会只关联我一个人了.jpg

# 功能

- 扫描分析
	- 杀毒检测-进程比对
	- 杀毒检测-WMIC
	- 检测管理员进程
	- 检测硬件信息
	- 检测Domain信息
	- 查询安装的软件
	- 查询管理员RDP登录来源
	- 查询.net兼容版本
	- 读取wifi密码
- 权限维持
	- 服务马
	- winrm后门
	- msdtc劫持
	- 令牌提权
	- 令牌降权
- 小工具
	- 关闭防火墙
	- 弹窗
	- 开启RDP
	- API添加用户
	- Defender 加白名单
	- 驱动K进程
	- 自删除
	- 删除RDP登录日志
	- 删除系统日志
	- 文件扩大，防止上传
	- HVNC
- 提权
	- SweetPotato
	- UAC
	- MS16-032
	- 其他一大堆土豆
- 域
	- ZeroLogon
	- PowerView
	- sAMSpoofing
	- noPAC
- Dump操作
	- Reg导出
	- comsvcsdll
	- minidump
	- dcsyncdump
	- 浏览器密码
	- 驱动dump内存

# todo

- ~微信密钥抓取(改为dump进程，真的要用的时候再去逆向吧)~ 
- ms17010
- 代理
- HVNC
- 读取RDP密码
- SharpDump
- mobaxteam 密码读取
- xshell 密码读取
- 浏览器密码读取
- 模拟程序假死
- 读取sqlserver保存密码

# 大量抄袭来源

https://github.com/422926799/csplugin

https://github.com/DeEpinGh0st/Erebus

还有各种稀奇古怪的，总之就是没有多少自己写的
