# GSB Bugfix Task
## 题面
登录失败消息区分账号不存在、密码错误和账号锁定，攻击者能批量枚举账号。account_enum_guard.py 的 validate 是核心，tests/test_account_enum_guard.py 15 个红。要修成对外统一返回通用失败文案和同一状态码，拒绝包含 user not found、wrong password、locked、不存在、密码错误等差异信息。15 个测试通过后，再用 1000 组随机消息和 32 线程并发校验，确认响应不可区分；不许改测试或硬编码文案。边界至少覆盖账号不存在、密码错误、锁定、内部 ID、空值和超长。

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
