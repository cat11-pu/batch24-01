# GSB Bugfix Task
## 题面
富文本评论要过一遍清洗：只保留少量排版标签，链接只允许 https，脚本、样式、iframe、SVG、MathML、事件属性和注释里的标签都要清掉，控制字符不能留在输出里。sanitize 在 html_sanitizer.py，十五个用例现在全部失败。输入可能是畸形嵌套或大小写混写，输出必须让危险片段彻底消失；标签和属性白名单由参数传入。改完我用 1500 条随机 HTML、26 个线程并发清洗；用例不许改，白名单不能写死。

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
