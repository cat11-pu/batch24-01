# GSB Bugfix Task
## 题面
JWT 验完签名就放行，payload 里没有 exp、iat 也能过，签发方和受众字段根本不看，过期令牌可以一直用。validate_claims 在 jwt_claims.py，现有 15 条测试全红。payload 得是字典，exp 和 iat 得是整数且 exp 晚于 iat；过期、未来签发、nbf 在未来、issuer 或 audience 不匹配、缺少必填字段、时间跨度超过上限都算失败。改完拿 1350 组随机 claim、25 个线程并发跑；测试文件不改，签发方和受众由调用方指定。

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
