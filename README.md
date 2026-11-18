# GSB Bugfix Task
## 题面
WAF 按签名表检查请求：每条签名有 id、目标区域、匹配串和分值，path、query、body 分开扫，百分号编码只解一次，大小写不敏感，命中累计，超过阈值拦截；目标区域不认识、类型非法、匹配串为空、分值为负都拒绝。waf_rules.py 的 inspect 负责检查，十五条用例眼下全挂。request 和 rules 都要校验，返回 action、score 和命中项；异常输入和并发检查结果必须一致。上线前用 1300 个随机请求、24 个线程压检查；测试文件别改，拦截阈值由使用方定。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
