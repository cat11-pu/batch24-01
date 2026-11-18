# GSB Bugfix Task
## 题面
实时协作的 WebSocket 握手只看连接能不能建，不校验 Origin，任意站点都能借用户浏览器连上内网服务。check_handshake 在 ws_origin_guard.py，仓库自带的十五条断言当前全是失败。Origin 必须是加密来源并和调用方给的集合完全一致，null、空串、通配、带端口、带账号、带路径、带尾斜杠、大写主机、换行、NUL、多个来源拼接都拒绝；Host 也要和 Origin 主机对得上。改完拿 1100 组随机握手头、24 个线程同时跑；测试文件别动，来源集合由参数传入。

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
