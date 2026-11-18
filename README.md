# GSB Bugfix Task
## 题面
账号锁定按原始用户名做 key，攻击者改大小写、加空格或 Unicode 归一化变体就能绕过锁定继续爆破。lockout_guard.py 的 validate 是核心，tests/test_lockout_guard.py 15 个红。要修成用户名先做大小写/空白/NFKC 归一化再计数，空值和超长拒绝。15 个用例跑绿后，再用 1000 组随机用户名和 32 线程并发校验，确认锁定不能绕过；不许改测试或硬编码用户名。边界至少覆盖大小写、前后空格、Unicode 归一化、空值和超长。

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
