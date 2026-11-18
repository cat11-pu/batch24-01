# GSB Bugfix Task
## 题面
网关的安全响应头现在可以随便配：HSTS max-age=0、CSP 默认全放行、X-Frame-Options ALLOW、Referrer-Policy unsafe-url 都能通过。header_policy.py 的 validate 接收 (头名, 头值)，tests/test_header_policy.py 15 个红。要修成按头名白名单和最小安全值校验，危险配置和 CR/LF 注入抛 ValueError。除了 15 个用例，验收还会用 1000 组随机响应头和 32 线程并发校验，确认没有放宽安全头；不许改测试或硬编码头名。边界至少覆盖 HSTS、CSP、X-Frame-Options、Referrer-Policy、Set-Cookie、换行和空名。

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
