# GSB Bugfix Task
## 题面
网关把 /debug、/actuator/env、/.env 和 /metrics 直接暴露到公网，里面能看到配置和密钥。debug_guard.py 的 validate 是核心，tests/test_debug_guard.py 15 个红。要修成调试和环境端点只允许内网或管理员，路径归一化后拒绝大小写、编码、分号和双斜杠变体。15 个红测之后，再用 1000 组随机路径和 32 线程并发校验，确认没有调试端点绕过；不许改测试或硬编码路径。边界至少覆盖 /debug、/actuator、/.env、/metrics、大小写、编码和双斜杠。

## 运行方式
```bash
python -m pytest tests -q
```

## 安全策略
`debug_guard.validate` 对请求路径先归一化再匹配可配置的敏感前缀（默认覆盖 `/debug`、
`/actuator`、`/.env`、`/metrics`、`/env`、`/config`）：

- 剥离 query/fragment，最多 4 轮百分号解码，拒绝畸形编码、控制字符与 NUL；
- 拒绝分号（matrix 参数）与反斜杠，折叠双斜杠并解析 `.`/`..` 段，统一小写；
- 命中敏感端点时仅内网 IP（`ipaddress.is_private`）或 `is_admin=True` 放行，公网抛 `ValueError`；
- 前缀可通过参数或环境变量 `DEBUG_GUARD_BLOCKED_PREFIXES`（逗号分隔）覆盖，无硬编码路径。

## 并发模糊校验
```bash
python fuzz_debug_guard.py
```
固定随机种子生成 1000 组路径（600 组敏感端点混淆变体 + 400 组正常路径），
以 32 线程并发校验：敏感变体必须全部拒绝、正常路径全部放行。

## 平台字段

所属领域：安全
子方向：系统安全
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
