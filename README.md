# GSB Bugfix Task
## 题面
tar 解压不检查 symlink/hardlink，链接能指向目标目录外，后续写入会落到系统路径。tar_guard.py 的 validate 接收 (name, type, linkname)，tests/test_tar_guard.py 15 个红。要修成拒绝绝对链接、.. 链接、设备文件和目标目录外条目，普通文件/目录才放行。15 个红测之后，再用 1000 组随机条目和 32 线程并发校验，确认不能借链接逃逸；不许改测试或硬编码路径。边界至少覆盖绝对链接、.. 链接、hardlink、设备文件、空链接和超长。

## 运行方式
```bash
python -m pytest tests -q
```

## 模糊 / 并发校验
`fuzz_tar_guard.py` 生成 1000 组混合安全与恶意条目（绝对链接、`..` 穿越、
hardlink、设备节点、空链接、超长、NUL、Windows 路径），用独立 oracle 交叉
核对，并以 32 线程并发重放，确认没有条目能借链接逃逸出目标目录：
```bash
python fuzz_tar_guard.py
```

## 平台字段

所属领域：安全
子方向：系统安全
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
