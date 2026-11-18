# GSB Bugfix Task
## 题面
内部服务要校验对端证书：主机名必须命中 SAN，通配符只能覆盖一级，有效期要包含当前时间，签名算法只认 SHA-256 和 SHA-384，SPKI 指纹必须落在调用方给的 pin 集合里。verify_peer 在 tls_pinning.py，十五个用例现在全部失败。cert 是包含 subject、san、not_before、not_after、sig_alg、spki_sha256 的字典，pins 是非空集合；空 SAN、弱算法、过期、未来生效、主机名不符、pin 不匹配和类型错误都要拒绝。改完我拿 1200 组随机证书、24 个线程并发校验；用例不能改，pin 集合由参数传入。

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
