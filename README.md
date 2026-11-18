# GSB Bugfix Task
## 题面
跳转和回调 URL 允许把 token、password、api_key 放在查询串里，浏览器历史、Referer 和代理日志都会泄漏。secret_url_guard.py 的 validate 是核心，tests/test_secret_url_guard.py 15 个红。要修成拒绝 URL 里的 password/token/api_key/secret 参数、userinfo 和片段，敏感值不能出现在查询串。15 个红测之后，再用 1000 组随机 URL 和 32 线程并发校验，确认没有密钥进 URL；不许改测试或硬编码参数名。边界至少覆盖 token、password、api_key、secret、userinfo、fragment 和编码参数名。

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
