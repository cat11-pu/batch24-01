# GSB Bugfix Task
## 题面
会话层要重做：登录要发不可预测的 ID，同一用户同一设备再次登录要轮换旧会话，闲置和绝对超时都要生效，设备绑定变化要失效，单用户并发会话数要有上限，撤销和按用户批量撤销必须立刻可见。login、touch、revoke、revoke_user 都在 session_manager.py，十五个用例目前全红。store 是调用方传入的字典；空用户、空设备、非字符串、时间倒流都要报错，未知会话 touch 返回 False，撤销未知会话返回 False。改完我开 30 个线程同时登录和 touch；测试不能改，超时和并发上限由参数传入。

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
