# GSB Bugfix Task
## 题面
备份和编辑器临时文件留在 web 根目录，/config.php.bak、/.env.old、/.git/config 能被直接下载。backup_guard.py 的 validate 是核心，tests/test_backup_guard.py 15 个红。要修成拒绝 .bak/.old/.swp/.swo/.git/.env 和常见备份后缀，路径归一化后判断。15 个用例跑绿后，再用 1000 组随机路径和 32 线程并发校验，确认没有备份泄漏；不许改测试或硬编码路径。边界至少覆盖 .bak、.old、.swp、.git、.env、大小写和编码点。

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
