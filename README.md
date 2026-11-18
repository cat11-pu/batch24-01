# GSB Bugfix Task
## 题面
压缩包解压前不检查压缩比、总解压大小、条目数和符号链接数量，zip bomb 能把磁盘和 inode 一起打满。zip_bomb_guard.py 的 validate_archive 是核心，tests/test_zip_bomb_guard.py 15 个红。要修成压缩比、总解压大小、条目数、单条目大小和 symlink 数量都在上限内，空包、负数和超限都明确拒绝。15 个红测之后，再用 1000 组随机包和 32 线程并发校验，确认不能解压炸弹；不许改测试或硬编码阈值。边界至少覆盖高压缩比、超大解压、条目过多、单条目超限、symlink 和负数。

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
