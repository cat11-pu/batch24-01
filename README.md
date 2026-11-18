# GSB Bugfix Task
## 题面
临时文件先检查再打开，检查和使用之间有 TOCTOU 窗口，攻击者能换掉路径。tmp_guard.py 的 validate 接收 (path, mode)，tests/test_tmp_guard.py 15 个红。要修成只允许 O_EXCL 原子创建、拒绝已存在文件、危险模式和路径穿越。15 个用例跑绿后，再用 1000 组随机路径和 32 线程并发校验，确认没有时间窗口；不许改测试或硬编码路径。边界至少覆盖已存在、追加模式、写模式、非法模式、空路径、NUL 和路径穿越。

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
