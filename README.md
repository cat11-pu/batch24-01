# GSB Bugfix Task
## 题面
多因素认证要按顺序推进：密码通过后才允许 TOTP，备份码是另一条路径，验证码格式不对、超过有效期、失败次数到上限、状态已锁定都不能继续，重置只能在激活后发生。step 在 mfa_orchestrator.py，十五条用例当前全红。state 必须带 status、user、factors、failed、locked、expires，event 只认四类；类型不符、顺序错误和并发重复激活都要挡住。压测时准备 1350 组随机验证流程、25 个线程并行推进；测试文件别改，锁定阈值交给使用方。

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
