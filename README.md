# GSB Bugfix Task
## 题面
OAuth PKCE 校验允许 plain、允许 verifier 为空、还接受大小写变体，授权码被截获后可以直接换 token。pkce_guard.py 的 verify 是核心，tests/test_pkce_guard.py 15 个红。要修成只允许 S256、challenge 和 verifier 必须匹配、长度和字符集合法、空值和编码变体拒绝。15 个用例跑绿后，再用 1000 组随机 PKCE 和 32 线程并发校验，确认不能降级；不许改测试或硬编码 challenge。边界至少覆盖 plain、空 verifier、错误 verifier、大小写、空值、换行和 NUL。

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
