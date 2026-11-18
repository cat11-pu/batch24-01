# GSB Bugfix Task
## 题面
审计日志现在直接把事件名和字段拼成一行写文件，换行、CRLF、ANSI、U+2028 能伪造日志行，password/token 明文落盘，字段没有白名单，32 线程并发写还会串行号。audit_log.py 是核心，tests/test_audit_log.py 15 个红。要修成结构化 JSON 单行、字段白名单和类型校验、password/token 脱敏、控制字符转义、原子追加和并发唯一序号。修完 15 个测试后，还要保证 1000 组随机事件没有伪造，32 线程并发写序号唯一；不许改测试或硬编码字段。边界至少覆盖换行、CRLF、ANSI、NUL、U+2028、超长值、未知字段、空事件、并发。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
