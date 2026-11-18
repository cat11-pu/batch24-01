# GSB Bugfix Task
## 题面
短信验证码重发没有冷却，攻击者能连续触发，短信费用和用户骚扰都失控。otp_resend_guard.py 的 validate 是核心，tests/test_otp_resend_guard.py 15 个红。要修成同一手机号 60 秒冷却、每小时上限、时间倒退和空号拒绝。15 个红测之后，再用 1000 组随机时间戳和 32 线程并发校验，确认不能绕过冷却；不许改测试或硬编码阈值。边界至少覆盖 0 秒、59 秒、60 秒、负时间、未来时间、空号和超限。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：系统安全
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
