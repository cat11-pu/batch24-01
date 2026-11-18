# GSB Bugfix Task
## 题面
用户自定义正则直接编译，嵌套量词和超长模式能把匹配拖死。regex_guard.py 的 validate 是核心，tests/test_regex_guard.py 15 个红。要修成拒绝嵌套量词、重复通配、超长模式和空模式，非法表达式抛 ValueError。15 个红测通过只是第一层；第二层用 1000 组随机模式和 32 线程并发校验，确认没有 ReDoS；不许改测试或硬编码模式。边界至少覆盖 (a+)+、(a|aa)+、(.*a){20}、超长、空值和非字符串。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：质量保障
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
