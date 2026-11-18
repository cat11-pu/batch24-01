# GSB Bugfix Task
## 题面
评论区把用户昵称和主页链接直接拼进 HTML，尖括号、引号、事件属性和 javascript: 协议都原样输出，存储型 XSS 一打一个准。render_comment 在 xss_escape.py，仓库附带的十五条断言眼下全是失败。要求文本做 HTML 实体转义，属性值加引号，链接只允许 https 且拒绝 javascript、data、vbscript、实体编码和大小写变体，控制字符和换行要处理。十五条通过后，我再用 1800 组随机文本和链接、40 路并发渲染，检查有没有标签或事件属性漏出；用例不许改，转义表也不能硬编码成只认几个字符。

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
