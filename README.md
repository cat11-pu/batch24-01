# GSB Bugfix Task
## 题面
网关拼接响应头时没有过滤换行，攻击者往文件名或跳转地址里塞 CRLF，就能凭空插入 Set-Cookie 和第二个响应体。build_header 在 response_split_guard.py，仓库里十五个用例现在都跑不过。要求头名只能是 token 字符且不能为空，头值出现 CR、LF、NUL、垂直制表、换页、U+2028、U+2029 或超过长度上限时抛 ValueError，普通值原样返回 name: value。修好后我会丢 1000 组随机头名和值、15 个线程同时构造；用例不许改，长度上限从参数传入。

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
