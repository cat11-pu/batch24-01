# GSB Bugfix Task
## 题面
老接口还在用 JSONP 输出数据，callback 参数直接拼进脚本，攻击者传 alert(1) 或带分号的表达式就能执行任意代码。jsonp_guard.py 的 wrap_jsonp 要负责白名单校验，随仓库给的 15 条断言眼下全红。callback 只能由字母、数字、下划线和点组成，首字符不能是数字；空值、括号、分号、斜杠、空白、换行、NUL、关键字和非字符串一律拒绝，长度上限由调用方决定。交付前我会用 1100 个随机 callback、16 个线程同时包装；既有断言不能改。

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
