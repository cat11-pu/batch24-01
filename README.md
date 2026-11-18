# GSB Bugfix Task
## 题面
MFA 备份码可以无限试，没有次数限制和锁定，六位备份码能被在线爆破。backup_code_guard.py 的 validate 是核心，tests/test_backup_code_guard.py 15 个红。要修成按用户计数、超过阈值锁定、窗口过期、空值和非法码拒绝。15 个测试通过后，再用 1000 组随机尝试和 32 线程并发校验，确认不能绕过锁定；不许改测试或硬编码次数。边界至少覆盖 0 次、超限、负时间、空码、非字符串和并发。

## 运行方式
```bash
python -m pytest tests -q
python scripts/stress_test.py        # 1000 组随机尝试 + 32 线程并发，校验锁定不可绕过
```

## 修复要点
- `validate([attempts, code])`：无状态校验，拒绝 0/负/非整数尝试次数、达到阈值的尝试，以及空码、非字符串、非 6 位数字、含空白/空字节/换行、全零码。
- `BackupCodeGuard`：按用户独立计数，达到 `max_failed_attempts` 即锁定；固定窗口过期后完整重置；锁定检查在码格式校验之前，锁定期内任何 payload 都只抛 `BackupCodeLockedError`。
- 线程安全：所有“检查+更新”在同一把锁内原子完成，并发爆破不会超过阈值。
- 时钟可注入，负时间（时钟回拨）通过钳制 elapsed=0 保证不会提前解锁。
- 阈值/窗口均为命名常量或构造参数，无硬编码次数；测试文件未改动。

## 平台字段

所属领域：安全
子方向：身份认证
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
