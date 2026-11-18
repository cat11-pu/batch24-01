# GSB Bugfix Task
## 题面
反向代理的 Host 校验现在直接放行：带端口、userinfo、后缀仿冒、IP 字面量、换行和空字节的 Host 都能过，缓存键也会被污染。host_guard.py 是核心，tests/test_host_guard.py 15 个红。要修成 Host 必须精确匹配白名单、只允许标准端口、拒绝 userinfo、IP、控制字符和后缀仿冒，缓存键使用规范化后的 host。修完 15 个测试后，还要保证 1000 组随机 Host 没有绕过，32 线程并发校验不串白名单；不许改测试或硬编码 Host。边界至少覆盖空 Host、带端口、userinfo、后缀仿冒、IP、换行、空字节。

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
