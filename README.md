# GSB Bugfix Task
## 题面
URL 规范化要消除歧义：协议只认 http/https，主机转小写并做 IDNA，默认端口去掉，点段要折叠，百分号编码统一，userinfo、反斜杠、控制字符、空主机和非法类型全部拒绝。canonicalize 在 url_canonical.py，十五个用例现在全红。输入必须是非空字符串，输出是可直接比较的规范形式；歧义写法不能悄悄放过，必须报错。改完我生成 1500 组随机 URL、28 个线程并发规范化；用例原样保留，允许协议由参数传入。

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
