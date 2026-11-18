# GSB Bugfix Task
## 题面
列表接口接受前端传的 page 和 size，传 size=100000 就能让数据库一次吐出全表，内存和带宽都被打满。page_size_guard.py 的 paginate 负责分页，用例共十五个，眼下没有一个通过。page 和 size 必须是整数，page 从 1 开始，size 限制在 1 到 100，total 不能为负也不能超过上限，布尔、浮点、字符串和 None 都拒绝，正常参数返回分页信息。验收拿 1100 个随机分页参数、18 个线程一起跑；测试文件不动，上限由调用方提供。

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
