# GSB Bugfix Task
## 题面
出站 URL 校验现在直接放行：file/gopher、内网 IP、localhost、十进制或十六进制 IP、userinfo、后缀仿冒都能过。url_guard.py 是核心，tests/test_url_guard.py 15 个红。要修成只允许 http 和 https、主机必须在白名单、解析后的 IP 不能是 loopback/private/link-local/reserved、拒绝 userinfo 和端口逃逸。修完 15 个测试后，还要保证 1000 组随机 URL 没有绕过，32 线程并发校验不串白名单；不许改测试或硬编码 URL。边界至少覆盖 file/gopher、localhost、127.0.0.1、169.254.169.254、十进制和十六进制 IP、userinfo、后缀仿冒。

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
