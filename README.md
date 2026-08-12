# Internet Applications

北京邮电大学国际学院（BUPT Queen Mary）**互联网应用**课程实验代码与报告整理。

本仓库包含课堂实验（Lab 3–8）示例、期末 **DHCP** 与 **DNS** 综合项目，以及 Lab 8 抓包分析报告。

## 目录结构

```text
.
├── CMakeLists.txt          # 统一构建配置
├── l3-*.c                  # Lab3：进程 / 文件 / 信号
├── l4-*.c                  # Lab4：文件描述符
├── l5.c                    # Lab5：主机名解析
├── l6-Echo*.c              # Lab6：Echo 客户端 / 服务端
├── l7-*.c                  # Lab7：简易文件传输
├── l8-report.MD            # Lab8：DHCP & DNS 抓包实验报告
├── l8-images/              # 报告截图
├── l8-packets/             # 抓包文件（.pcapng）
├── DHCP-Project/           # DHCP 客户端 / 服务端
└── DNS-Project/            # 分层 DNS 解析系统
```

文件名前缀对应实验序号，例如 `l3` 表示 Lab 3。

## 实验一览

| 实验 | 内容 | 主要文件 |
|------|------|----------|
| Lab3 | 进程创建、`exec`、文件读写、`lseek`、信号处理 | `l3-*.c` |
| Lab4 | 文件描述符与读写示例 | `l4-1.c`, `l4-2.c` |
| Lab5 | 主机名 / 地址解析（`hostent`） | `l5.c` |
| Lab6 | UDP Echo 客户端 / 服务端 | `l6-EchoClient.c`, `l6-EchoServer.c` |
| Lab7 | 简易文件传输客户端 / 服务端 | `l7-Client.c`, `l7-Server.c` |
| Lab8 | 使用 Wireshark 抓取并分析 DHCP / DNS 报文 | `l8-report.MD`, `l8-images/`, `l8-packets/` |

## DHCP 项目

路径：`DHCP-Project/`

基于 UDP 实现简易 DHCP 客户端与服务端，覆盖 Discover / Offer / Request / ACK 等流程，支持租约管理、续租（Renew / Rebind）与地址池分配。

| 文件 | 说明 |
|------|------|
| `dhcp-client.c` | DHCP 客户端 |
| `dhcp-server.c` | DHCP 服务端 |
| `dhcp-project.h` | 公共协议定义与配置 |

默认地址池示例：`192.168.0.2` 起，网关 / 服务端 `192.168.0.1`（详见头文件宏定义）。

## DNS 项目

路径：`DNS-Project/`

模拟分层 DNS 体系：本地服务器、根服务器、TLD、二级权威服务器，支持记录查询与简单缓存。

| 组件 | 默认地址（见 `dns-project.h`） |
|------|--------------------------------|
| 本地 DNS | `127.1.1.1` |
| 根 DNS | `127.2.2.1` |
| in-addr.arpa | `127.2.2.2` |
| TLD A / B | `127.3.3.1` / `127.3.3.2` |
| Second A / B | `127.4.4.1` / `127.4.4.2` |

配套 `.txt` 记录文件与 `*-cache.txt` 缓存文件可按需编辑，用于实验场景配置。

## 构建与运行

依赖：C99 编译器、CMake ≥ 3.5、Linux 网络环境（部分实验可能需要 root 或特殊权限绑定 53 / 67 / 68 端口）。

```bash
mkdir -p build && cd build
cmake ..
make
```

常用目标示例：

```bash
./l6-EchoServer
./l6-EchoClient
./dhcp-server
./dhcp-client
```

DNS 相关可执行文件由源码编译生成后，需按实验说明分别启动各层级服务器，再使用 `dns-client` 发起查询。

## 技术要点

- **系统调用**：`fork` / `exec`、文件描述符、信号
- **Socket 编程**：TCP / UDP、字节序、`sockaddr_in`
- **DHCP**：BOOTP 兼容报文、Option 解析、租约链表
- **DNS**：Header / Question / RR 编解码、迭代解析、缓存

## 许可

课程实验代码，仅供学习交流使用。
