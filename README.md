# GSB Bugfix Task
## 题面
IP 白名单用字符串前缀匹配，10.0.0.1 能匹配 10.0.0.10，短写和十进制 IP 也能绕过。ip_allow_guard.py 的 validate 是核心，tests/test_ip_allow_guard.py 15 个红。要修成解析成标准 IP 后按网段匹配，拒绝短写、十进制、十六进制、IPv4 映射、端口、空白和控制字符。15 个红测之后，再用 1000 组随机 IP 和 32 线程并发校验，确认不能绕过；不许改测试或硬编码网段。边界至少覆盖前缀相似、短写、十进制、十六进制、IPv4 映射、端口和空白。

## 运行方式
```bash
python -m pytest tests -q
```

## 白名单配置与压测

允许的网段通过环境变量配置（逗号分隔的 CIDR，未配置时默认全部拒绝），
按 `IP_ALLOW_LIST`、`IP_ALLOWLIST`、`IP_WHITELIST` 的顺序读取：

```bash
IP_ALLOW_LIST="10.0.0.0/8,192.168.1.0/24" python -m pytest tests -q
```

`validate` 只接受规范的点分十进制 IPv4 字符串，先用严格正则和
`ipaddress.IPv4Address` 双重校验，再按网段做位掩码匹配；短写（前导零）、
十进制/十六进制整数、IPv4 映射地址、端口、CIDR 后缀、空白和控制字符一律拒绝。

独立压测脚本（自带与被测代码无关的判定 oracle，1000 组随机 IP、32 线程）：

```bash
IP_ALLOW_LIST="10.0.0.0/8,192.168.1.0/24" python stress_ip_allow_guard.py
# 换随机种子：STRESS_SEED=123 python stress_ip_allow_guard.py
```

## 平台字段

所属领域：安全
子方向：系统安全
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
