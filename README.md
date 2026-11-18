# GSB Bugfix Task
## 题面
临时文件跟随 symlink，攻击者先放一个指向 /etc/passwd 的链接，写入就落到系统文件。symlink_guard.py 的 validate 是核心，tests/test_symlink_guard.py 15 个红。要修成拒绝 symlink、绝对路径、路径穿越、空字节和超长路径，只允许目标目录内的普通文件。15 个红测之后，再用 1000 组随机路径和 32 线程并发校验，确认不能借链接逃逸；不许改测试或硬编码路径。边界至少覆盖 symlink、绝对路径、..、空字节、空值和超长。

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
