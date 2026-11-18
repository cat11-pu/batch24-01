# GSB Bugfix Task
## 题面
会话票据要封装成不透明串：内容带 kid、签发时间和业务字段，HMAC 覆盖编码后的主体，密钥可以轮换但 kid 必须在表里，过期、未来签发、篡改、缺段、错密钥和畸形 base64 全部拒绝。cookie_crypto.py 的 seal 和 open_token 负责整套封装，仓库十五条断言眼下全红。入参必须是字典，keys 是非空映射，now 是整数，ttl 正数；合法票据还原出原字段。验收准备 1300 个随机票据、24 个线程一起封装和解封；测试文件保持原样，密钥表和 ttl 由调用方给出。

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
