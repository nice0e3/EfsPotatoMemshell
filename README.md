# EfsPotatoMemshell



EfsPotatoMemshell - 提权与内存马一体化工具
CVE-2021-36942 + 内存马功能整合


usage: EfsPotatoMemshell <cmd|memshell> [pipe] [port]
  cmd: 直接执行命令
  memshell: 启动内存马
  pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
  port -> 内存马监听端口 (default=80)

示例：
  EfsPotatoMemshell "whoami" lsarpc
  EfsPotatoMemshell memshell efsrpc 8080
  EfsPotatoMemshell memshell          (使用默认设置)

  ![image](https://github.com/user-attachments/assets/a30a9493-4a60-4fac-982d-1701f2468768)
