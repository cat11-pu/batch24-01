# GSB Bugfix Task
## 题面
下载响应要生成 Content-Disposition：文件名里的换行、回车、NUL、引号、反斜杠、控制字符、路径分隔符和超长值都必须拒绝，非 ASCII 文件名要按 RFC 5987 编码，普通名字要能直接下发。content_disposition.py 的 build_disposition 负责拼值，仓库里的十五条用例目前都过不了。filename 不能为空，fallback 也不能带控制字符；合法输入返回可直接写进响应的值。上线前用 1200 个随机文件名、22 个线程并发拼值；用例不许动，长度阈值交给调用方。

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
