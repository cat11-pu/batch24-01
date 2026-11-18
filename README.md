# GSB Bugfix Task
## 题面
静态目录没有关闭 listing，访问 /uploads/ 或 /static/ 会列出全部文件。directory_guard.py 的 validate 是核心，tests/test_directory_guard.py 15 个红。要修成目录请求必须有 index 或明确禁止 listing，拒绝空目录、编码斜杠、双斜杠和路径穿越。15 个测试通过后，再用 1000 组随机路径和 32 线程并发校验，确认没有目录枚举；不许改测试或硬编码路径。边界至少覆盖 /uploads/、/static/、编码斜杠、双斜杠、..、空路径和超长。

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
