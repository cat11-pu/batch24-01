# GSB Bugfix Task
## 题面
SAML 响应不校验 Audience、Recipient、NotOnOrAfter 和签名引用，拿着别的租户的断言也能登录。saml_guard.py 的 validate 是核心，tests/test_saml_guard.py 15 个红。要修成 Audience/Recipient 必须匹配、时间窗有效、签名引用唯一且覆盖断言。15 个红测之后，再用 1000 组随机响应和 32 线程并发校验，确认断言不能挪用；不许改测试或硬编码租户。边界至少覆盖 Audience 不符、Recipient 不符、过期、未来、重复断言和空签名。

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
