# SharpEventLog

## 简介
读取登录过本机的登录失败或登录成功的所有计算机信息，在内网渗透中快速定位运维管理人员。

## 使用说明

### cmd.exe
```
> SharpEventLog.exe

Author: Uknow
Github: https://github.com/uknowsec/SharpEventLog

Usage: SharpEventLog.exe -4624
       SharpEventLog.exe -4625
```

![](https://github.com/uknowsec/SharpEventLog/blob/master/images.png)



### Cobalt Strike

```
execute-assembly /path/to/SharpEventLog.exe
```
