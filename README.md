# GSB Bugfix Task
## 题面
报表分页接口 page_size 和 offset 没有上限，page_size=10^9 或负 offset 能让数据库扫全表。pagination_guard.py 的 validate 接收 (page_size, offset)，tests/test_pagination_guard.py 15 个红。要修成 page_size 1..200、offset 0..10^7 的整数，拒绝 0、负数、超限、布尔、浮点、字符串和 None。15 个测试通过后，再用 1000 组随机分页和 32 线程并发校验，确认没有放大查询；不许改测试或硬编码上限。边界至少覆盖 page_size=0、负 offset、超限、布尔、浮点、字符串和 None。

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
