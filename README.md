## DHCP 客户端模拟

该项目使用 [Scapy](https://scapy.net/) 实现 DHCP 客户端的四步交互（Discover → Offer → Request → ACK）。

### 准备环境

项目使用 [uv](https://github.com/astral-sh/uv) 管理依赖。首次运行请安装依赖：

```bash
uv sync
```

### 运行示例

由于 Scapy 构造 DHCP 报文需要底层网络访问，请使用 root 或具备 `CAP_NET_RAW` 权限的用户运行：

```bash
sudo uv run python main.py --iface eth0
```

- `--iface`：指定要发送 DHCP 报文的网卡。若省略，默认使用 Scapy 配置的接口。
- `--timeout`：等待服务器响应的超时时间（默认 5 秒）。
- `--retries`：失败后的重试次数（默认 3 次）。
- `--clients`：模拟的 DHCP 客户端数量。大于 1 时将自动并发执行多次握手（默认 1）。
- `--concurrency`：并发握手的最大数量，仅在 `--clients`>1 时生效（默认 10）。
- `--mac-prefix`：为模拟客户端生成 MAC 时使用的前缀（例如 `02:00:00`）。
- `--seed`：生成客户端 MAC 时使用的随机种子，便于复现。
- `--client-mac`：单客户端模式下强制使用指定的 MAC 地址。
- `--list-ifaces`：仅显示 Scapy 识别到的网卡列表，然后退出。

示例：并发模拟 200 个客户端对 DHCP 服务器进行压测

```bash
sudo uv run python main.py --iface eth0 --clients 200 --concurrency 50 --mac-prefix 02:de:ad:be
```

成功执行后，会打印服务器分配的 IP、租期、路由、DNS 等信息；若失败，会输出失败原因。
