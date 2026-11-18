# GSB Bugfix Task
## 题面
Webhook 接收端要同时验内容和时鲜度：HMAC 覆盖原始字节，时间偏离太大直接失败，同一个签名只许消费一次，头和 body 的类型都要先校验，摘要比较不能提前返回。verify 在 webhook_hmac.py，套件十五条用例现在全部红。headers 必须带 x-signature 和 x-timestamp，签名写成 sha256=十六进制，secret 不能为空，cache 由调用方传入；缺失、格式错、过期、未来、重放和篡改都算失败。改完我拿 1500 组随机请求、30 个线程并发验签；用例不许改，窗口由参数传入。

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
