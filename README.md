# GSB Bugfix Task
## 题面
反向代理和上游服务器对 Content-Length 与 Transfer-Encoding 的解释不一致，攻击者可以构造 CL.TE 或 TE.CL 请求，把后半段夹带成下一个请求。smuggle_guard.py 的 parse_request 是核心，tests/test_smuggle_guard.py 15 个红。要修成同时出现 CL/TE、重复 CL、重复 TE、混淆 TE、负值、十六进制、带符号和空字节都拒绝，合法请求正常解析。15 个用例跑绿后，再用 1000 组随机头和 32 线程并发解析，确认没有走私；不许改测试或硬编码头名。边界至少覆盖 CL.TE、TE.CL、重复头、混淆 TE、负值、控制字符和空头。

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
