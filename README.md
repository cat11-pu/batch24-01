# GSB Bugfix Task
## 题面
限流按 X-Forwarded-For 的第一个值做 key，攻击者伪造多个 IP 就能绕过。client_key_guard.py 的 validate 是核心，tests/test_client_key_guard.py 15 个红。要修成只在可信代理时采信 XFF、取最右侧可信跳、拒绝空值、非法 IP、换行和超长。15 个用例跑绿后，再用 1000 组随机头和 32 线程并发校验，确认不能绕过限流；不许改测试或硬编码 IP。边界至少覆盖空值、unknown、逗号链、非法 IP、换行、NUL 和超长。

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
