# GSB Bugfix Task
## 题面
用户资料接口把数据库行整个序列化返回，password_hash、ssn、api_key 这些字段跟着响应一起出门。serialize_user 在 field_filter.py，十五个用例当前全军覆没。要求只输出调用方点名的字段，用户对象里出现敏感键、请求里点名敏感键或通配符都抛 ValueError，字段列表必须是非空字符串列表，用户必须是字典，嵌套字典里的敏感键也要挖出来拒绝。改完我拿 1200 组随机用户和字段、20 个线程同时序列化；断言不许改，敏感键名单从参数传入。

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
