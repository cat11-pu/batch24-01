# GSB Bugfix Task
## 题面
HTTP 响应头值直接来自用户输入，CR/LF、NUL、ANSI 和编码换行能拆出额外响应头。http_header_guard.py 的 validate 是核心，tests/test_http_header_guard.py 15 个红。要修成头值拒绝 CR、LF、NUL 和控制字符，编码换行也要拒绝，非法值抛 ValueError。15 个红测不是终点；验收再用 1000 组随机头值和 32 线程并发校验，确认没有响应拆分；不许改测试或硬编码值。边界至少覆盖 CRLF、LF、NUL、ANSI、编码 %0d%0a、Unicode 行分隔和超长值。

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
