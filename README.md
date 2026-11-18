# GSB Bugfix Task
## 题面
分页游标要签名并绑定查询条件：客户端不能改 offset、limit 或过滤条件，换密钥、过期、未来签发、结构不对都要拒绝，limit 有上限，offset 不能为负，游标里必须带签发时间。encode_cursor 和 decode_cursor 在 cursor_pagination.py，十五个用例现在全红。用标准库做 HMAC 和 base64，payload 必须是字典；合法游标解出来要和原 payload 一致。改完我生成 1200 个随机游标、22 个线程并发解码；测试不能改，TTL 和 limit 上限由参数传入。

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
