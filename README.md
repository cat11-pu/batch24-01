# GSB Bugfix Task
## 题面
缓存键只取 URL，不包含 Host、X-Forwarded-Host、Authorization 和 Cookie，攻击者能污染共享缓存。cache_key_guard.py 的 validate 接收头列表，tests/test_cache_key_guard.py 15 个红。要修成缓存键纳入所有影响响应的头，Host/XFH 必须匹配允许列表，敏感头不能参与公共缓存。15 个红测之后，再用 1000 组随机头和 32 线程并发校验，确认不能污染缓存；不许改测试或硬编码头名。边界至少覆盖 Host、XFH、Authorization、Cookie、端口、后缀仿冒和空值。

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
