# GSB Bugfix Task
## 题面
密码重置链接现在直接拿请求里的 Host 拼 URL，攻击者把 Host 改成仿冒域名或带端口、userinfo 的地址，就能把重置令牌引到自己的站点。reset_link.py 是核心，tests/test_reset_link.py 15 个红。要修成 Host 必须精确匹配允许列表、只能走 https、拒绝端口、userinfo、IP、后缀仿冒、控制字符和空值。修完 15 个测试后，还要保证 1000 组随机 Host 没有污染链接，32 线程并发生成不串允许列表；不许改测试或硬编码 Host。边界至少覆盖后缀仿冒、带端口、userinfo、IP、换行、空 Host、尾点。

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
