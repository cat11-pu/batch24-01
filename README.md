# GSB Bugfix Task
## 题面
SRI integrity 只检查有没有前缀，空哈希、错误算法和多个冲突哈希都能过，CDN 被换文件也发现不了。sri_guard.py 的 validate 是核心，tests/test_sri_guard.py 15 个红。要修成只接受 sha256/sha384/sha512、哈希长度正确、base64 字符合法、多个哈希必须一致，拒绝空值和注入。15 个红测之后，再用 1000 组随机 integrity 和 32 线程并发校验，确认不能绕过；不许改测试或硬编码哈希。边界至少覆盖空值、错误算法、短哈希、非法字符、多哈希冲突、换行和 NUL。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
