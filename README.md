# GSB Bugfix Task
## 题面
IP 白名单用字符串前缀匹配，10.0.0.1 能匹配 10.0.0.10，短写和十进制 IP 也能绕过。ip_allow_guard.py 的 validate 是核心，tests/test_ip_allow_guard.py 15 个红。要修成解析成标准 IP 后按网段匹配，拒绝短写、十进制、十六进制、IPv4 映射、端口、空白和控制字符。15 个红测之后，再用 1000 组随机 IP 和 32 线程并发校验，确认不能绕过；不许改测试或硬编码网段。边界至少覆盖前缀相似、短写、十进制、十六进制、IPv4 映射、端口和空白。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：系统安全
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
