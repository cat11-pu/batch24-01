# GSB Bugfix Task
## 题面
用户从普通角色提权到管理员后会话不轮换，旧会话继续拿着管理员权限。privilege_guard.py 的 validate 接收 (old_role, new_role, session_id, rotated)，tests/test_privilege_guard.py 15 个红。要修成角色变化必须轮换会话、旧 session 失效、空值和非法角色拒绝。15 个红测之后，再用 1000 组随机状态和 32 线程并发校验，确认提权不能复用旧会话；不许改测试或硬编码角色。边界至少覆盖 user->admin、admin->user、会话未轮换、空 session、非法角色和并发。

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
