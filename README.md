# GSB Bugfix Task
## 题面
OAuth 授权码的授权码现在能猜、不绑客户端、不过期、能重复用，撤销和轮换也不生效。oauth_code.py 是核心，tests/test_oauth_code.py 15 个红。要修成随机且不可预测的授权码、绑定客户端 ID、redirect_uri 和 PKCE verifier、按 TTL 过期并清理、一次校验后作废、撤销和轮换立即失效。15 个用例跑绿后，再用 1000 组随机授权码、客户端和过期时间和 32 线程并发校验，确认没有重放和越权；不许改测试或硬编码授权码。边界至少覆盖空客户端、空 code、ttl 为 0、重复换 token、换客户端重放。

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
