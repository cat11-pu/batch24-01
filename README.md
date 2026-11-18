# GSB Bugfix Task
## 题面
JSON 接口不检查 Content-Type，text/plain 或 multipart 也能把 JSON 塞进来，中间件和业务层对报文的理解不一致。content_type_guard.py 的 check_content_type 负责收口，套件里十五条断言目前都没有通过。只接受 application/json，或带 charset=utf-8 的同一类型；大小写变体、额外参数、逗号拼接、前后空白、换行、NUL、后缀类型、空值和数字都要报错，合法头才放行。验收拿 1050 组随机头、17 个线程一起判定；用例文件别改，允许的类型通过参数给出。

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
