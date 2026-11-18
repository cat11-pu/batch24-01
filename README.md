# GSB Bugfix Task
## 题面
CSP nonce 可预测、重复使用或直接写成静态值，攻击者能猜出 nonce 注入脚本。csp_guard.py 的 validate 是核心，tests/test_csp_guard.py 15 个红。要修成 nonce 随机、长度足够、每次响应唯一、只允许 base64 字符，空值和重复值拒绝。15 个测试通过后，再用 1000 组随机 nonce 和 32 线程并发校验，确认不能预测；不许改测试或硬编码 nonce。边界至少覆盖空值、短值、纯数字、静态值、重复值、换行和 NUL。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
