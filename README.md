# GSB Bugfix Task
## 题面
邮箱验证令牌现在是用户 ID 加时间戳，能猜、能重放，验证后也不失效。email_verify_guard.py 的 validate 是核心，tests/test_email_verify_guard.py 15 个红。要修成令牌随机、绑定邮箱、一次性、带过期时间，空值、短令牌、数字令牌和控制字符拒绝。15 个红测之后，再用 1000 组随机令牌和 32 线程并发校验，确认不能重放；不许改测试或硬编码令牌。边界至少覆盖空值、短令牌、纯数字、换行、重放、过期和跨邮箱。

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
