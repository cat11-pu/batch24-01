# GSB Bugfix Task
## 题面
按 RFC 8693 做令牌交换时，请求字段一个都不能松：grant_type 必须精确命中，subject_token 非空且有长度区间，token 类型落在允许集合，audience 等于当前客户端，scope 非空，requested_token_type 只认 access_token，actor_token 出现时也要校验类型和长度。token_exchange.py 的 exchange 负责这套校验，仓库十五条测试眼下全挂。入参得是字典，now、client_id 和允许类型作为参数传入；字段缺失、类型不符、越界和客户端不匹配都算失败。验收拿 1300 个随机交换请求、24 个线程一起处理；测试文件原样保留，允许类型由调用方定。

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
