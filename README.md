# GSB Bugfix Task
## 题面
XML 解析允许内部实体和外部实体，billion laughs 和外部 DTD 能撑爆内存或读本机文件。xml_entity_guard.py 的 validate 是核心，tests/test_xml_entity_guard.py 15 个红。要修成拒绝 DOCTYPE、ENTITY、外部 DTD、参数实体和实体展开超限。15 个用例跑绿后，再用 1000 组随机 XML 和 32 线程并发校验，确认不能实体膨胀；不许改测试或硬编码实体。边界至少覆盖内部实体、外部实体、billion laughs、参数实体、外部 DTD 和空值。

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
