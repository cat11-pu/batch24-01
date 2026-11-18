# GSB Bugfix Task
## 题面
解压前不检查压缩比和条目数，zip bomb 能撑爆磁盘和 inode。zip_bomb_guard.py 的 validate 接收 (compressed, uncompressed, entries)，tests/test_zip_bomb_guard.py 15 个红。要修成压缩比、总解压大小、条目数和单条目大小都在上限内，空包和负数拒绝。15 个用例跑绿后，再用 1000 组随机包和 32 线程并发校验，确认不能解压炸弹；不许改测试或硬编码阈值。边界至少覆盖高压缩比、超大解压、条目过多、负数、空包和单条目超限。

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
