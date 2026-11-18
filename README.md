# GSB Bugfix Task
## 题面
JSON 和上传入口没有 body 上限，超大请求能把内存打满。body_limit.py 的 validate 是核心，tests/test_body_limit.py 15 个红。要修成只接受 1 到 1 MiB 的整数大小，拒绝 0、负数、超限、浮点、布尔、字符串和 None。15 个红测之后，再用 1000 组随机大小和 32 线程并发校验，确认没有绕过；不许改测试或硬编码阈值。边界至少覆盖 0、负数、1 MiB+1、超大、浮点、布尔、字符串和 None。

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
