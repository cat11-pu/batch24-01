# GSB Bugfix Task
## 题面
报表查询要按方言拼 SQL，但表名、列名、排序字段都来自前端，稍不注意就能注入；过滤值必须全部参数化，LIKE 里的通配符要转义。sql_builder.py 的 build_query 要按 schema 校验标识符，方言只认 postgres 和 mysql，标识符按方言加引号，未知表列、空列、非法排序方向、负数 limit 一律拒绝。验收时准备 1400 组随机查询、30 个线程并发构造；测试保持原样，schema 从调用方传入。

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
