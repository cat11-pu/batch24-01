# GSB Bugfix Task
## 题面
会话 Cookie 现在只要名字对就下发，Domain 写成父域、SameSite=None 不带 Secure、__Host- 前缀还带 Domain，浏览器会把会话带到别的站点。cookie_guard.py 的 validate 是核心，tests/test_cookie_guard.py 15 个红。要修成按前缀规则、SameSite/Secure/HttpOnly 组合和 Domain 范围校验，非法 Cookie 属性抛 ValueError。15 个红测只是第一层；第二层用 1000 组随机 Cookie 头和 32 线程并发校验，确认没有放宽属性、也不串状态；不许改测试或硬编码属性。边界至少覆盖父域 Domain、SameSite=None、__Host- 前缀、空名、换行和重复属性。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：身份认证
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
