# GSB Bugfix Task
## 题面
缓存层按原始 URL 做键，/admin.css、/admin.js、/admin%2ecss 这类路径能绕过缓存规则，把私有页面缓存成静态资源。cache_guard.py 的 validate 是核心，tests/test_cache_guard.py 15 个红。要修成路径规范化后再判断静态后缀，拒绝大小写变体、编码点、分号、空字节、双斜杠和路径穿越。15 个用例跑完后，再用 1000 组随机路径和 32 线程并发校验，确认没有缓存欺骗；不许改测试或硬编码路径。边界至少覆盖 .css/.js、%2e、分号、空字节、双斜杠和大小写。

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
