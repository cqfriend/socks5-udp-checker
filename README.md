# SOCKS5 UDP & UoT Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8.svg)](https://golang.org)

用于全方位检测 SOCKS5 代理服务器的 **UDP 连通性**、**UDP-over-TCP (UoT v1 / v2)**、**DNS 解析支持**、**ATYP 远端域名解析能力** 以及 **NAT 穿透类型 (Full Cone / Symmetric)** 的专业命令行工具。

---

## 📖 简介 (Overview)

很多 SOCKS5 代理在实际生产环境中有各种各样的 UDP 限制：
1. **单端口拦截**：部分网络或云防火墙拦截了 UDP 123 (NTP) 端口，但 UDP 53 (DNS) 正常；
2. **ATYP 域名远端解析缺失**：在 TCP 下可以解析域名，但在 UDP 包头中只支持 IP 字节（`ATYP 0x01`），遇到域名（`ATYP 0x03`）直接丢包；
3. **NAT 映射类型不佳**：代理节点为对称型 NAT (Symmetric NAT)，导致联机游戏、P2P 下载和 WebRTC / 语音通话无法正常打洞连通；
4. **不支持原生 UDP 但支持 UoT**：代理只支持 `sing-box` / `Clash.Meta` 体系的 UDP-over-TCP（UoT v1 / v2）。

本工具提供一键式、开箱即用的深度检测方案，帮助网络工程师、代理用户和开发者准确定位代理的 UDP 特性与瓶颈。

---

## ✨ 核心特性 (Features)

- **六维全景检测与真实出口 IP**：
  0. **代理真实出口 IP 查询**：自动通过 `ip.sb` (GeoIP) 等接口获取代理实际对外请求的真实出口 IP、国家、省市及 ISP 运营商信息
  1. **标准 SOCKS5 UDP (NTP 123)**：RFC 1928 `UDP ASSOCIATE` 模式，测量 RTT 延迟、服务器时间与 Stratum
  2. **DNS 查询检测 (UDP 53)**：向公共 DNS（默认 `223.5.5.5:53`）查询 `one.one.one.one`，排查单端口拦截
  3. **ATYP 域名远端解析检测**：对比 IPv4 (`0x01`) 与 FQDN 域名 (`0x03`)，精准识别代理是否缺少远端 UDP DNS 模块
  4. **UDP-over-TCP v1**：检测 `sp.udp-over-tcp.arpa` 单流分包协议支持
  5. **UDP-over-TCP v2**：检测 `sp.v2.udp-over-tcp.arpa` 新型高性能流式连接协议支持
  6. **NAT 穿透类型检测 (STUN)**：基于 RFC 3489 / 5389 规范，一键测出代理的 NAT 类型（Full Cone / Symmetric / Restricted Cone）
- **丰富的代理输入格式**：
  - `username:password@host:port`
  - `socks5://username:password@host:port`
  - `host:port:username:password`
  - `socks5://host:port:username:password`
  - `socks5:host:port:username:password`
  - `host:port`
  - `socks5://host:port`
  - `socks5:host:port`
  - 支持 IPv6 地址（例如 `[::1]:1080`、`[::1]:1080:user:pass`）
- **灵活的指定模式**：默认 `all` 执行完整全景诊断；也可通过 `-dns`、`-atyp`、`-nat`、`-mode uot-v2` 单独运行特定项。
- **深度 Debug 模式**：通过 `-debug` 查看完整的 SOCKS5 握手、RFC 1929 认证、UDP ASSOCIATE 绑定以及 STUN/DNS 包细节。
- **纯 CLI、零多余依赖**：极速启动，适合终端即时排查与脚本自动化。
- **一键跨平台编译**：内置 `build.sh`，直接编译生成 Linux、macOS、Windows 的各架构二进制。

---

## 🚀 编译与安装 (Installation)

确保本地环境已安装 Go（1.20 或更高版本）：

```bash
# 编译本地可执行文件
go build -o socks5-udp-checker ./cmd

# 或一键编译所有平台（Linux / macOS / Windows）二进制
chmod +x build.sh
./build.sh
```

---

## 💻 命令行参数 (Usage)

```text
SOCKS5 UDP & UoT (UDP-over-TCP) Checker

Usage:
  socks5-udp-checker -proxy <proxy> [options]
  socks5-udp-checker <proxy> [options]

Proxy Formats:
  • username:password@host:port
  • socks5://username:password@host:port
  • host:port:username:password
  • socks5://host:port:username:password
  • socks5:host:port:username:password
  • host:port
  • socks5://host:port
  • socks5:host:port

Options:
  -proxy <string>        SOCKS5 代理地址
  -target <string>       NTP 测试服务器 (默认: "ntp1.aliyun.com:123")
  -ntp <string>          -target 的别名
  -dns-server <string>   DNS 测试服务器 (默认: "223.5.5.5:53")
  -stun-server <string>  STUN 测试服务器 (默认: "stun.miwifi.com:3478")
  -mode <string>         测试模式: all, standard, uot-v1, uot-v2, uot, dns, atyp, nat, stun, ip (默认: "all")
  -ip                    仅查询并输出代理实际出口 IP 与归属地
  -dns                   仅测试 DNS 解析 (UDP 53)
  -atyp                  仅测试 ATYP 域名与 IPv4 远端解析能力
  -nat, -stun            仅测试代理节点的 NAT 穿透类型 (STUN)
  -timeout <dur>         超时时间 (默认: 5s)
  -debug                 输出协议底层通讯的 Debug 日志
  -v, -version           查看版本信息
  -h, -help              查看帮助说明
```

---

## 📝 使用示例 (Examples)

### 1. 全景综合检测（默认）
全面测试 NTP 123、DNS 53、ATYP 域名远端解析、UoT v1/v2 以及 NAT 类型：
```bash
./socks5-udp-checker -proxy user:pass@127.0.0.1:1080
```

输出示例：
```text
==================================================
         SOCKS5 UDP & UoT Checker
==================================================
Proxy:       user:******@127.0.0.1:1080
NTP Target:  ntp1.aliyun.com:123
DNS Target:  223.5.5.5:53
STUN Target: stun.miwifi.com:3478
Mode:        all
Timeout:     5s
--------------------------------------------------
[1/6] Standard SOCKS5 UDP (NTP Port 123):
      Status:  [SUCCESS] SUPPORTED
      Detail:  RTT: 32.418ms | Stratum: 2 | Offset: +1.205ms | Time: 15:40:01 UTC

[2/6] DNS Resolution (UDP Port 53 -> 223.5.5.5:53):
      Status:  [SUCCESS] SUPPORTED
      Detail:  RTT: 26.115ms | Query: one.one.one.one -> 1.1.1.1

[3/6] ATYP Remote Domain Resolution (FQDN 0x03 vs IPv4 0x01):
      Status:  [SUCCESS] SUPPORTED (Full Remote DNS)
      Detail:  IPv4 (0x01): Supported (31.8ms) | Domain (0x03): Supported (34.2ms)
      Note: Fully Supported (Proxy resolves domain names in UDP relay headers)

[4/6] UDP-over-TCP v1 (sp.udp-over-tcp.arpa):
      Status:  [SUCCESS] SUPPORTED
      Detail:  RTT: 35.104ms | Stratum: 2 | Offset: +1.189ms

[5/6] UDP-over-TCP v2 (sp.v2.udp-over-tcp.arpa):
      Status:  [SUCCESS] SUPPORTED
      Detail:  RTT: 30.542ms | Stratum: 2 | Offset: +1.201ms

[6/6] NAT Type Detection (STUN: stun.miwifi.com:3478):
      Status:  [SUCCESS] Full Cone NAT (NAT 1)
      Detail:  Type: Full Cone NAT (NAT 1) | Mapped Endpoint: 123.45.67.89:54321
      Behavior: Full Cone: Outbound UDP allows all unsolicited inbound traffic; ideal for P2P/Gaming

==================================================
Summary:
  • Standard SOCKS5 UDP             : SUPPORTED
  • DNS Resolution                  : SUPPORTED
  • ATYP Remote Domain Resolution   : SUPPORTED (Full Remote DNS)
  • UDP-over-TCP v1                 : SUPPORTED
  • UDP-over-TCP v2                 : SUPPORTED
  • NAT Type Detection              : Full Cone NAT (NAT 1)
==================================================
```

### 2. 测试 DNS (UDP 53) 单独连通性
用于排查是不是因为 NTP (123 端口) 被机房封锁而导致 UDP 误报失败：
```bash
./socks5-udp-checker -proxy 127.0.0.1:1080 -dns
```

### 3. 测试 ATYP 域名远端解析能力
排查代理是否只支持填 IP、不能解析域名：
```bash
./socks5-udp-checker -proxy 127.0.0.1:1080 -atyp
```
若出现：
- `IPv4 (0x01): Supported | Domain (0x03): Failed`
则说明代理本身开启了 UDP 中继，但在服务端没有实现 UDP 域名解析功能，客户端需要使用 Fake-IP 或本地解析。

### 4. 测试 NAT 穿透类型 (STUN)
```bash
./socks5-udp-checker -proxy 127.0.0.1:1080 -nat
```
可测得：
- `Full Cone NAT (NAT 1)`：全锥型，任何外网主机均可直接连入，联机与 P2P 体验极佳；
- `Restricted Cone NAT (NAT 2/3)`：受限锥型；
- `Symmetric NAT (NAT 4)`：对称型，访问不同目标会动态更换外网端口，无法进行 P2P 联机打洞。

### 5. 开启详细 Debug 日志
```bash
./socks5-udp-checker -proxy user:pass@127.0.0.1:1080 -debug
```

---

## ⚙️ 退出状态码 (Exit Codes)

| 状态码 | 含义 |
| :---: | :--- |
| `0` | 检测成功（所测试协议至少有一项或全部被代理支持） |
| `1` | 检测失败（所有模式均不支持、连接超时或参数格式错误） |

可在自动化运维或 CI/CD 流程中轻松集成：
```bash
if socks5-udp-checker -proxy 127.0.0.1:1080 -timeout 3s >/dev/null 2>&1; then
    echo "Proxy UDP is healthy!"
fi
```

---

## 📄 许可证 (License)

本项目基于 [MIT License](LICENSE) 开源。
