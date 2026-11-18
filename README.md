# GSB Bugfix Task
## 题面
授权同意要能查能撤：用户和客户端不能为空，scope 列表非空且每项都在允许集合里，重复 scope 拒绝，ttl 正数，同一用户同一客户端只保留一个有效授权，重新授权要让旧授权失效，撤销未知授权返回 False，过期或 scope 不足时 check 返回 False。grant、revoke、check 在 consent_registry.py，十五条用例当前全部失败。store 是字典，时间戳为整数；类型错误、越权和并发授权都要挡住。上线前用 1400 份随机授权、26 个线程压操作；测试文件不许动，scope 集合由使用方维护。

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
