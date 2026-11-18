# GSB Bugfix Task
## 题面
账号找回要防刷和可审计：提交时用户、答案和 case ID 都要校验，答案至少三条且不能为空，同一用户 24 小时内只能提交一次，审核人不能是申请人，决定只认 approve 和 reject，过期案件返回 expired，已决案件不能重复审核，并发审核只能落一次。submit 和 review 在 account_recovery.py，十五条用例眼下全挂。store、answers、decision 都要校验，时间戳为整数；异常输入和越权都报错。压测安排：1250 份随机找回单、22 个线程并行审核；用例不许动，冷却时间交给使用方。

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
