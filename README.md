# GSB Bugfix Task
## 题面
OAuth 回调现在不校验 state、不绑客户端、授权码能重复用、redirect_uri 只做前缀匹配，PKCE 也可有可无。oauth_guard.py 是核心，tests/test_oauth_guard.py 15 个红。要修成 state 必须匹配且一次性、授权码只能消费一次、redirect_uri 必须精确匹配注册值、PKCE 必须 S256 且 verifier 对得上、client_id 必须匹配。修完 15 个测试后，还要保证 1000 组随机 state/code/redirect 没有绕过，32 线程并发消费同一 code 只能成功一次；不许改测试或硬编码测试输入。边界至少覆盖空 state、空 code、state 重放、code 重放、redirect 带 userinfo 或 fragment。

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
