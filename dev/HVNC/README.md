# BIE 修改版本

从反弹连接修改成了正向连接，适用于cs等代理环境的正向连接，避免反弹出网时候的相关问题。

使用方法就是编译后，执行

`Client.exe 监听端口`

然后使用`Server.exe 远程ip 远程端口`来连接HVNC

后续可能会把大灰狼的那个屏幕控制扒出来，感觉那个对于弱网环境比较好，VNC有一个缺点就是太吃流量了，直接一张张截图发送过去。

大灰狼不仅还有灰度还有什么屏幕差异补偿算法，感觉特别牛逼，有空再扒。

# HiddenVNC


**HF有老哥放出来了自己的tinynuke修复版，我这份之前做的也就开源出来吧**  

hvnc是一种用来解决异地登陆（比如浏览器，操作系统/插件版本，语言环境，时区等对用户的系统进行指纹识别）的方法。  

传统的vnc，即远程桌面控制，很容易被用户看到操作，无法实现隐藏的目的。

hvnc可以利用一些鲜为人知的Windows功能，例如CreateDesktop和跨进程窗口子类来实现VNC运行的不可见环境。

详细一点的介绍可以看这篇文章：[HVNC恶意软件介绍、分析、现状及应对措施](https://bbs.pediy.com/thread-264956.htm "HVNC恶意软件介绍、分析、现状及应对措施") ，里面有较为详细的原理及应用讲解。

## 编译
在Visual Studio 2019中打开解决方案，选择Realease/x86即可编译。默认客户端ip为127.0.0.1，如有需要请自行修改。

## 运行
编译后，在项目 /Release 下运行server.exe,然后运行client.exe，就可以看到一个vnc界面。
如果界面全黑，请右键点击标题栏，选择start explorer或其他选项。

## 检测及调试
hvnc新建的桌面很难通过简单的方式切换，所以为了方便验证及测试，在 /anti-hvnc 里有一个切换及检测桌面和进程的软件，源代码：[HiddenDesktopViewer](https://github.com/AgigoNoTana/HiddenDesktopViewer "HiddenDesktopViewer") ，具体用法详见该Repo的介绍。

## 支持
* 未测试以下系统
  * Windows XP SP3
  * Windows Server 2003
  * Windows Vista
* 确认支持以下系统
  * Windows Server 2008
  * Windows 7
  * Windows Server 2012
  * Windows 8/8.1
  * Windows 10


## 注意
我（簞純）对您使用此软件可能执行的任何操作概不负责。您对使用此软件采取的任何措施承担全部责任。请注意，此应用程序仅用于教育目的，切勿被恶意使用。通过下载软件或软件的源代码，您自动接受此协议。
