# GSB Bugfix Task
## 题面
网关把 /debug、/actuator/env、/.env 和 /metrics 直接暴露到公网，里面能看到配置和密钥。debug_guard.py 的 validate 是核心，tests/test_debug_guard.py 15 个红。要修成调试和环境端点只允许内网或管理员，路径归一化后拒绝大小写、编码、分号和双斜杠变体。15 个红测之后，再用 1000 组随机路径和 32 线程并发校验，确认没有调试端点绕过；不许改测试或硬编码路径。边界至少覆盖 /debug、/actuator、/.env、/metrics、大小写、编码和双斜杠。

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
