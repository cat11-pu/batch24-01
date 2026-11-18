# GSB Bugfix Task
## 题面
登录成功后会话 ID 不轮换，攻击者可以先塞一个固定 session 再让受害者登录，之后继续用同一个 ID。session_fixation.py 是核心，tests/test_session_fixation.py 15 个红。要修成登录时必须生成全新随机会话 ID、旧 ID 立即失效、绑定用户、退出登录清理。修完 15 个测试后，还要保证 1000 组随机会话没有固定成功，32 线程并发登录只产生一个有效会话；不许改测试或硬编码 ID。边界至少覆盖空用户、空 session、重复登录、退出后重放、攻击者预置 ID。

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
