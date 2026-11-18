# GSB Bugfix Task
## 题面
设备授权流程里 user_code 只做非空判断，客户端 ID 和用户确认的客户端不比对，过期时间也不看，攻击者能拿别人的码换令牌。check_device_code 在 oauth_device.py，仓库给的十五个用例当前没有一个通过。code、user_code、client_id 都必须是非空字符串且长度合规，user_code 不能带空白和横线以外的字符，客户端必须和已批准的一致，过期时间必须是整数且晚于当前时间，任何一项不满足都报错。最后用 1050 组随机设备码、18 个线程同时校验；原有用例保持原样，客户端白名单由调用方给出。

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
