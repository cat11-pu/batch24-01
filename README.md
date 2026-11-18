# GSB Bugfix Task
## 题面
JSON 解析入口允许重复键、NaN/Infinity、超深嵌套和多个文档，后面的键能覆盖前面的权限字段。json_guard.py 的 validate 是核心，tests/test_json_guard.py 15 个红。要修成重复键、非标准常量、超深嵌套、尾随内容、BOM 和超长输入都拒绝，非法 JSON 抛 ValueError。把 15 个用例跑绿后，还要用 1000 组随机 JSON 和 32 线程并发校验，确认权限字段不会被覆盖；不许改测试或硬编码键。边界至少覆盖重复键、NaN、Infinity、深嵌套、多文档、尾逗号和 BOM。

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
