# GSB Bugfix Task
## 题面
API Key 认证现在几乎不设防：密钥可预测、明文存储、不绑用户、不过期、吊销不生效、没有 scope、旋转后旧 key 还能用。api_key_guard.py 是核心，tests/test_api_key_guard.py 15 个红。要修成随机密钥、哈希存储、绑定用户、按 TTL 过期、scope 校验、吊销和旋转立即失效。修完 15 个测试后，还要保证 1000 组随机用户、密钥和 scope 没有绕过，32 线程并发校验不串 scope；不许改测试或硬编码密钥。边界至少覆盖空用户、空密钥、过期、吊销、跨用户、scope 不足。

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
