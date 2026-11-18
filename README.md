# GSB Bugfix Task
## 题面
CSRF 防护要绑定会话并防重放：令牌带会话、签发时间和签名，非安全方法必须校验，Origin 要命中允许集合，过期、换签名、换会话、篡改和重复使用都拒绝，旋转后旧令牌立刻失效。issue 和 check 在 csrf_engine.py，十五个用例当前全红。session 和 secret 不能为空，method 只认标准方法，ttl 正数；合法请求返回 True。改完我拿 1350 组随机请求、25 个线程并发校验；用例不能改，允许来源和 ttl 由参数传入。

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
