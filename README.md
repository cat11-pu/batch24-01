# GSB Bugfix Task
## 题面
WebAuthn 注册要管住挑战：随机值要够长并绑定用户和 RP ID，有有效期且只能消费一次，验证时 Origin 与 RP ID 精确匹配，签名计数器必须递增，重放和并发消费都要拦住。webauthn_challenge.py 的 create_challenge 和 verify 负责整套流程，仓库十五条断言眼下全红。user、rp_id、origin 不能为空，store 是字典，ttl 正数；异常输入、过期和重放都算失败。验收拿 1250 个随机挑战、23 个线程压注册；断言文件不许动，ttl 由调用方给出。

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
