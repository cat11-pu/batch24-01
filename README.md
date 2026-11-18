# GSB Bugfix Task
## 题面
OAuth redirect_uri 用前缀匹配，https://app.example.com.evil.com 和带 userinfo 的地址也能通过，授权码会被送到攻击者站点。oauth_redirect_guard.py 的 validate 是核心，tests/test_oauth_redirect_guard.py 15 个红。要修成 redirect_uri 精确匹配注册值、只允许 https、拒绝端口、userinfo、路径、fragment 和编码变体。15 个红测之后，再用 1000 组随机 URI 和 32 线程并发校验，确认授权码不能改道；不许改测试或硬编码 URI。边界至少覆盖后缀仿冒、userinfo、端口、路径、fragment、编码和空值。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：身份认证
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
