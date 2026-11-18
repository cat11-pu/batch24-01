# GSB Bugfix Task
## 题面
导出 CSV 时单元格直接写用户输入，以 =、+、-、@ 开头的值会被表格软件当公式执行。csv_guard.py 的 validate 是核心，tests/test_csv_guard.py 15 个红。要修成公式前缀、前导空白/制表符/换行、NUL 和超长值都拒绝或转义，非法单元格抛 ValueError。15 个用例之外，继续用 1000 组随机单元格和 32 线程并发校验，确认公式不会落地；不许改测试或硬编码单元格。边界至少覆盖 =、+、-、@、前导空白、制表符、换行和 NUL。

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
