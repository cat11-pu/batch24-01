# GSB Bugfix Task
## 题面
JWT 只验签名不验 audience、issuer 和 typ，拿别的服务签发的 token 也能登录。jwt_aud_guard.py 的 validate 接收 claims 列表，tests/test_jwt_aud_guard.py 15 个红。要修成 aud/iss 必须匹配、exp/nbf 有效、typ 必须是 JWT，空值和类型错误拒绝。15 个用例跑绿后，再用 1000 组随机 claims 和 32 线程并发校验，确认不能跨服务复用；不许改测试或硬编码 issuer。边界至少覆盖 aud 不符、iss 不符、过期、未来、typ 错误、空值和类型错误。

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
