# GSB Bugfix Task
## 题面
MFA 备份码可以无限试，没有次数限制和锁定，六位备份码能被在线爆破。backup_code_guard.py 的 validate 是核心，tests/test_backup_code_guard.py 15 个红。要修成按用户计数、超过阈值锁定、窗口过期、空值和非法码拒绝。15 个测试通过后，再用 1000 组随机尝试和 32 线程并发校验，确认不能绕过锁定；不许改测试或硬编码次数。边界至少覆盖 0 次、超限、负时间、空码、非字符串和并发。

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
