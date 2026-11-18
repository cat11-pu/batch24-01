# GSB Bugfix Task
## 题面
OAuth 授权时把用户同意的 scope 直接当成可用权限，申请 read 却能拿到 write，带星号的 scope 还会被当成全权限。check_scope 在 scope_guard.py，现成十五个用例全部挂掉。要求 granted 和 required 都是非空字符串列表，元素不能为空、不能含星号或冒号通配，大小写必须一致，required 里每一项都要在 granted 里出现，类型不对同样报错。改好以后我构造 1250 组随机 scope 组合、24 个线程同时判定；原有用例不许改，scope 集合由参数传入。

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
