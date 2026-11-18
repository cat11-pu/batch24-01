# GSB Bugfix Task
## 题面
会话撤销要能级联：按用户撤销时所有活动会话立刻失效，刷新令牌和记住登录凭据一起清掉，返回实际撤销数量；按设备撤销只影响该设备；用户和原因缺了直接拒收，store 和会话列表必须合规，重复撤销返回零，两个线程同时撤销不能重复计数。session_revocation.py 的 revoke_user_sessions 和 revoke_device 负责执行，仓库里的十五条测试眼下全挂。会话条目要带 status、device 和 refresh_id，时间取整数；坏输入和越权一律算失败。批量演练：1280 组随机会话、23 个线程一起撤销；断言文件保持原样，原因长度由使用方定。

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
