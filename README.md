# GSB Bugfix Task
## 题面
用户搜索条件直接传给 Mongo 查询，$ne、$gt、$regex、$where 这些操作符可以绕过登录和字段过滤。nosql_guard.py 是核心，tests/test_nosql_guard.py 15 个红。要修成只允许普通键值、拒绝所有以 $ 开头的操作符、拒绝嵌套操作符和列表注入，非法条件明确报错。修完 15 个测试后，还要保证 1000 组随机条件没有操作符注入，32 线程并发校验不串状态；不许改测试或硬编码字段。边界至少覆盖 $ne、$gt、$or、$where、$regex、$exists、嵌套对象和列表值。

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
