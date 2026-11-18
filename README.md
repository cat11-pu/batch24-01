# GSB Bugfix Task
## 题面
Basic 认证要按 RFC 解析凭据：scheme 只能写 Basic，base64 必须规范且能解码，解码后只能有一个冒号，用户名和密码都不能为空、不能带控制字符、长度受限，用户必须存在，密码比较不能提前返回。basic_auth.py 的 authenticate 负责验证，套件十五条测试眼下全部失败。users 是用户名到密码的字典；空凭据、错误 scheme、畸形 base64、多余冒号、未知用户和错误密码都算失败，验证通过返回用户名。交付前拿 1200 个随机认证串、22 个线程一起解析；测试保持原样，最大长度交给调用方。

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
