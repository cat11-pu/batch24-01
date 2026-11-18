# GSB Bugfix Task
## 题面
GraphQL 查询入口没有深度、别名和片段限制，一个请求可以靠嵌套选择、批量别名和片段递归把解析量放大几千倍。graphql_guard.py 是核心，tests/test_graphql_guard.py 15 个红。要修成限制查询深度、别名数、片段递归和总成本，拒绝 introspection、循环片段和超长查询，非法输入明确报错。修完 15 个测试后，还要保证 1000 组随机查询没有绕过，32 线程并发校验不串状态；不许改测试或硬编码查询。边界至少覆盖深嵌套、别名炸弹、片段循环、introspection、超长、空查询、非字符串。

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
