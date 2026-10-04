# bsf

[English](README_EN.md) | 中文

## 简介

bsf（“本地收发”的拼音缩写）是 [magic wormhole](https://magic-wormhole.readthedocs.io/en/latest/) 协议的 Go 实现，fork 自 [psanford/wormhole-william](https://github.com/psanford/wormhole-william)，提供端到端加密的文件 / 目录 / 文本传输命令行工具。两台计算机输入同一个“虫洞码”即可建立连接，并与官方 Python 客户端 [magic-wormhole](https://github.com/warner/magic-wormhole) 互通。

bsf 的特点是**局域网优先**：默认情况下一次发送完全不出局域网——发送端内嵌一个 rendezvous 服务器并在本地生成口令码，接收端通过子网广播自动发现发送端，全程不依赖任何公网服务器，口令码也不会离开本网络。需要局域网之外的接收端时，加 `--relay` 即可叠加一条公网腿。

## 安装

使用 go 工具链安装：

```
go install github.com/dwdcth/bsf@latest
```

或从 [GitHub Releases](https://github.com/dwdcth/bsf/releases) 下载预编译二进制（tar.gz 包，已剥离调试符号）：

| 系统 | 架构 |
| --- | --- |
| macOS（darwin） | amd64、arm64 |
| Linux | amd64、arm64、arm v5 / v6 / v7 |
| Windows | amd64、arm64、386 |
| FreeBSD | amd64 |
| NetBSD | amd64 |

## 快速用法

发送文件或目录（目录会作为 zip 打包传输）：

```
bsf send file.txt
bsf send /path/to/dir
```

发送文本（`-` 表示从 stdin 读取；既不带参数也不带 `--text` 时进入交互输入）：

```
bsf send --text "你好"
echo hello | bsf send --text -
```

接收端把口令码直接作为参数即可（等价于 `bsf receive CODE`），也可以运行 `bsf receive` 后按提示输入：

```
bsf 3-cinnamon-chalk-wizard
bsf receive
```

接收文件 / 目录时会提示 `ok? (y/N):`，输入 `y` 确认；默认拒绝覆盖已存在的同名文件。相关选项：

- `--yes`（`-y`）：跳过确认并覆盖同名文件
- `--out`（`-o`）：指定接收目录，默认当前目录

## 特性一览

- **口令码自动复制剪贴板**：依次尝试 `pbcopy`（macOS）、`clip`（Windows）、`wl-copy`（Wayland）、`xclip` / `xsel`（X11）等剪贴板工具；都没有时（例如纯 ssh 会话）回退 OSC 52 终端转义序列，由终端模拟器自己完成复制，kitty、iTerm2、Windows Terminal、WezTerm、alacritty、foot 均支持（tmux 内需开启 `set-clipboard`）。`--disable-clipboard` 可关闭。接收到的文本消息同样会复制到剪贴板（上限 1 MiB）。
- **多流并行传输**：`--parallel`（默认 4，发送 / 接收均可用）把文件切分为连续块，每条流独立派生记录密钥；文件和目录都支持，仅限 bsf ↔ bsf，对 Python 客户端自动回退标准单流。小于 8 MiB 的传输自动使用单流（多流握手开销不划算，单流对 WiFi 也更友好）；显式指定 `--parallel` 时始终尊重所给值。
- **UDP 打洞直连（P2P）**：双方都在 NAT 后时，先经 ICE 协商打洞（候选经现有加密信令通道交换，STUN 学公网映射），成功则以 QUIC 多流直连——不再绕公网中继；打洞失败自动回退中继转发。默认开启，`--ice=false`（或 `BSF_NO_ICE=1`）关闭；STUN 端点可用 `--stun` 指定，默认用公共服务器，自建 `bsf server` 的 STUN 会自动通告。多流与断线续传在打洞路径上同样生效。
- **WebSocket 中继（relay-ws-v1）**：`--ws-relay wss://...` 提供一个走 443 端口的兜底中继，可白嫖 Cloudflare Workers 免费额度（见 `contrib/cloudflare-relay/`），边缘只见密文。
- **断线自动续传**：transit 连接中断后双方保留状态，重连后从各流断点继续，不重发已传数据，最终 ack 校验整个文件的 sha256。
- **Shell 补全**：可补全口令码本身（nameplate 与奇偶词表），见[下文](#shell-补全)。
- 其他：进度条（`--hide-progress` 关闭）、`--verify` 校验串确认、`--qr` 二维码显示发送码（实验性）、`bsf server` 独立启动局域网 rendezvous 服务器、`--relay` / `--relay-url` 走公网。

## 常用选项

`bsf send`：

| 选项 | 说明 |
| --- | --- |
| `--text string` | 发送文本而非文件，`-` 从 stdin 读取 |
| `--code string` | 自定义口令码 |
| `-c, --code-length int` | 口令码长度（词数） |
| `--parallel int` | 并行流数量，默认 4；小于 8 MiB 自动单流（仅 bsf 接收端支持） |
| `--relay` | 同时把口令码注册到公网中继 |
| `-v, --verify` | 显示校验串并等待对端确认 |
| `--qr` | 以二维码显示发送码（实验性） |
| `--hide-progress` | 不显示进度条 |
| `--disable-clipboard` | 不复制口令码到剪贴板 |

`bsf receive`（裸码 `bsf CODE` 形式同样适用）：

| 选项 | 说明 |
| --- | --- |
| `-y, --yes` | 跳过确认并覆盖同名文件 |
| `-o, --out string` | 接收目录，默认 `.` |
| `--parallel int` | 并行流数量，默认 4（发送端提供时生效） |
| `-v, --verify` | 显示校验串 |
| `--hide-progress` | 不显示进度条 |
| `--disable-clipboard` | 不把收到的文本复制到剪贴板 |

全局：

| 选项 | 说明 |
| --- | --- |
| `--relay-url string` | 指定 rendezvous 服务器，也可用环境变量 `WORMHOLE_RELAY_URL` |
| `--ice` | UDP 打洞直连，默认开；`--ice=false` 或 `BSF_NO_ICE=1` 关闭 |
| `--stun strings` | 逗号分隔的 STUN 端点（`stun:host:port`），也可用 `BSF_STUN`；缺省时：接收端跟随发送端通告（自建服务器）→ 公共 STUN |
| `--ws-relay string` | wss:// WebSocket 兜底中继，也可用 `BSF_WS_RELAY` |

## 工作原理与端口

默认模式下一次发送完全在局域网内完成：发送端内嵌一个 rendezvous 服务器、本地生成口令码，并应答来自局域网的发现探测——不联系公网中继：

```
# 机器 A
$ bsf send file.txt
Send mode: local network
On the other computer on this network, please run: bsf <code>
Wormhole code is: 28471-torpedo-newborn

# 同一局域网的机器 B（自动发现发送端）
$ bsf 28471-torpedo-newborn
Rendezvous: ws://192.168.31.37:40009/ws (local network)
```

接收端通过子网广播探测（在 udp 53534 上发送 `bsf1 Q <nameplate>`），持有该 nameplate 的机器单播应答自己的地址。选择广播而不是 mDNS，是因为 macOS 把 udp 5353 独占交给系统响应进程，跨机发现会静默失败。若本地没有找到服务器，接收端回退公共中继 `ws://relay.magic-wormhole.io:4000/v1`，并打印一条说明（本地广播发现了几台服务器等），便于判断该修哪一端。

固定端口与随机回退：

| 端口 | 协议 | 用途 |
| --- | --- | --- |
| 40009 | tcp | 内嵌 / 独立 rendezvous 服务器，被占用时回退随机端口 |
| 40010 | tcp | transit 文件传输监听，被占用时回退随机端口 |
| 53534 | udp | 子网广播发现 |
| 3478 | udp | `bsf server --stun` 的 STUN 服务（打洞用），可用 `--stun <addr>` 改 |

传输路径优先级（任一失败自动降级，全程密文）：**直连 TCP → UDP 打洞（ICE + QUIC 多流）→ 中继**；中继里配置了 `--ws-relay` 时优先 WebSocket 中继，否则 TCP 中继（`bsf server --transit` 自建或公共 `transit.magic-wormhole.io:4001`）。

打洞路径的 UDP 接收缓冲无法在运行时调大（socket 归 ICE 库所有）；Linux 默认约 208 KiB，高吞吐传输可能因内核丢包重传跑不满带宽。有需要可在系统级调大，对新发起的传输生效，也惠及其他 UDP 程序：

```
sudo sysctl -w net.core.rmem_default=7340032    # 立即生效
echo 'net.core.rmem_default=7340032' | sudo tee /etc/sysctl.d/99-bsf.conf
sudo sysctl --system                            # 重启后仍生效
```

（7 MiB 为 QUIC 建议的接收缓冲大小；macOS 上对应 `net.inet.udp.recvspace`。）

开防火墙的机器需要放行：

```
ufw allow 53534/udp && ufw allow 40009:40010/tcp     # firewalld 同理
```

## 公网中继（--relay）

`--relay`（或显式 `--relay-url`）让局域网之外的接收端也能连接：发送同时在两条 rendezvous 腿上进行——公网中继生成口令码，内嵌服务器镜像同一个码，先到的接收端胜出，另一条腿被取消。中继不可达时（3 秒 TCP 探测超时）安静地回退纯局域网模式：

```
$ bsf send --relay file.txt
Send mode: relay + local network
```

## 独立 rendezvous 服务器（bsf server）

`bsf server` 启动一个常驻的 rendezvous 服务器，并通过 udp 广播通告：

```
$ bsf server
Rendezvous server listening on [::]:41352 (advertised via udp broadcast)
Use: bsf --relay-url ws://127.0.0.1:41352/ws ...
Use: bsf --relay-url ws://192.168.31.37:41352/ws ...
```

`--addr` 指定监听地址（默认 `:0` 随机端口，如 `--addr :40009` 固定端口）。之后两端传 `--relay-url ws://<lan-ip>:<port>/ws`（或设置 `WORMHOLE_RELAY_URL`）即可。

两个配套开关让自建部署完全不依赖公共服务：

- `--stun <addr>`（默认 `:3478`，空串关闭）：内嵌 STUN 服务器，帮双方学公网映射打洞；发现协议会随 rendezvous 一起通告它，发送端也可显式 `--stun stun:<lan-ip>:3478`。
- `--transit <addr>`（默认关闭）：标准 magic-wormhole TCP transit 中继，打洞失败时的转发兜底走自己的服务器而非公共中继。

```
$ bsf server --addr :40009 --stun :3478 --transit :4001
Rendezvous server listening on [::]:40009 (advertised via udp broadcast)
STUN server listening on :3478 (udp)
Transit relay listening on 127.0.0.1:4001
...
      (fallback transit relay: 127.0.0.1:4001)
      (stun: stun:192.168.31.37:3478)
```

另见 `contrib/cloudflare-relay/`：一个可直接部署到 Cloudflare Workers 的 WebSocket 中继（`--ws-relay`），零服务器成本、走 wss 443 端口。

文件传输优先在局域网内直连（先交换 direct-tcp-v1 地址提示，公网 transit 中继只是兜底），文本消息只经过 rendezvous 服务器。注意：这个服务器是面向个人 / 局域网的轻量实现，没有 nameplate 过期和限流，请勿暴露到公网。广播发现要求两台机器处于同一子网。

## 并行流与断线续传

两个 bsf 客户端之间的文件传输默认使用多条 transit 流并行（`--parallel`，默认 4，发送端和接收端都有该选项）：文件被切分为连续块，每条流负责一块；每条流为每次传输（包括每次续传尝试）独立派生记录密钥，记录 nonce 不会重复使用。对 Python magic-wormhole 客户端自动使用标准单流协议。

transit 连接中途断开时，双方保留状态，接收端上报每条流已收到的位置，重连后从这些位置继续，已传数据不会重发；最终 ack 校验整个文件的 sha256。若与 rendezvous 服务器的连接本身断开，或某一端退出，传输照常失败。

## Shell 补全

支持 bash / zsh / fish / powershell，按 `bsf shell-completion -h` 中的说明启用。补全对 `bsf receive <TAB>` 和裸 `bsf <TAB>` 都生效：给出 `--relay-url` 时向该服务器查询 nameplate，否则先向局域网内广播发现到的所有 rendezvous 服务器查询，找不到本地服务器才回退公共中继；口令码的单词部分按奇偶词表规则补全。

## 从源码构建

bsf 使用 go modules，需要 go 工具链 >= 1.11。克隆仓库后在顶层目录执行：

```
go build -trimpath -ldflags "-s -w" -o bsf .
```

## 作为 Go 库使用

`wormhole` 包可以直接作为库调用，文档见 <https://pkg.go.dev/github.com/dwdcth/bsf/wormhole?tab=doc>。发送文本示例：

```go
var c wormhole.Client

code, status, err := c.SendText(ctx, "hello")
if err != nil {
	log.Fatal(err)
}
fmt.Printf("Wormhole code is: %s\n", code)

s := <-status
if !s.OK {
	log.Fatalf("Send error: %s", s.Error)
}
```

更多用法参考 [cmd](https://github.com/dwdcth/bsf/tree/master/cmd) 与 [examples](https://github.com/dwdcth/bsf/tree/master/examples) 目录。

## 基于 wormhole-william 的第三方项目

- [rymdport](https://github.com/Jacalz/rymdport)：跨平台 Magic Wormhole 图形界面
- [riftshare](https://github.com/achabra2/riftshare)：桌面文件分享应用
- [termshark](https://github.com/gcla/termshark)：tshark 的终端 UI
- [tmux-wormhole](https://github.com/gcla/tmux-wormhole)：tmux 集成
- [wormhole-william-mobile](https://github.com/psanford/wormhole-william-mobile)：Android 应用
