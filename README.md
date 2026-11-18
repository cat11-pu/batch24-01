# GSB Bugfix Task
## 题面
WebSocket 握手现在不校验 Origin，任意站点都能连上来读消息。ws_origin.py 的 validate 是核心，tests/test_ws_origin.py 15 个红。要修成 Origin 必须 https、精确匹配允许列表、拒绝端口、userinfo、路径、fragment、null 和 IP。跑绿 15 个用例之后，第二层用 1000 组随机 Origin 和 32 线程并发校验，确认没有跨站连接；不许改测试或硬编码 Origin。边界至少覆盖 http 降级、后缀仿冒、null、端口、userinfo、路径和空值。

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
