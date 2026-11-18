# GSB Bugfix Task
## 题面
多租户 API 令牌现在这套API 令牌能猜、不绑租户、不过期、能重复用，撤销和轮换也不生效。tenant_api_key.py 是核心，tests/test_tenant_api_key.py 15 个红。要修成随机且不可预测的API 令牌、绑定租户归属和 scope、按 TTL 过期并清理、一次校验后作废、撤销和轮换立即失效。15 个用例跑绿后，再用 1000 组随机令牌、租户 ID、scope 和过期时间和 32 线程并发校验，确认没有重放和越权；不许改测试或硬编码API 令牌。边界至少覆盖空租户、空令牌、ttl 为 0、越权 scope、撤销后重放。

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
