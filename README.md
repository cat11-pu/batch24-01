# GSB Bugfix Task
## 题面
HSTS 头由租户自己填，max-age 写成 0、负数、小数或不足半年都能存进配置，preload 还能在不带子域的情况下打开。hsts_guard.py 里的 hsts_header 负责生成，套件里那十五条断言目前全红。max-age 必须是整数且落在半年到两年之间，includeSubDomains 和 preload 只接受布尔值，开 preload 必须同时开子域，类型错误或越界一律 ValueError，合法配置返回可直接下发的头字符串。验收准备 900 份随机配置、16 个线程一起生成；用例不许改，上下界由调用方给。

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
