# GSB Bugfix Task
## 题面
管理接口只允许 GET 和 POST，但 X-HTTP-Method-Override 和大小写变体能把 TRACE、CONNECT、DELETE 带进来，反向代理还会把奇怪方法原样转发。method_guard.py 的 validate 是核心，tests/test_method_guard.py 15 个红。要修成方法名大小写归一后只接受 GET/POST，覆盖头、空方法、控制字符和超长方法明确拒绝。15 个用例跑绿后，再用 1000 组随机方法和 32 线程并发校验，确认没有方法覆盖；不许改测试或硬编码方法。边界至少覆盖 TRACE、CONNECT、DELETE、大小写、空值、换行和覆盖头。

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
