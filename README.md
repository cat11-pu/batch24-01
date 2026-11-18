# GSB Bugfix Task
## 题面
密码策略只要求长度 >=6，常见密码、用户名密码和全数字都能过。password_policy.py 的 validate 是核心，tests/test_password_policy.py 15 个红。要修成长度、字符类别、常见密码、用户名包含和重复字符检查，弱密码抛 ValueError。15 个红测之后，再用 1000 组随机密码和 32 线程并发校验，确认弱密码不能注册；不许改测试或硬编码密码。边界至少覆盖空密码、短密码、常见密码、全数字、用户名密码、重复字符和超长。

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
