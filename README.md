# GSB Bugfix Task
## 题面
内部任务队列用 pickle 传对象，反序列化入口没有做任何限制，精心构造的 GLOBAL 和 REDUCE 指令可以在 worker 上执行任意命令。loads_safe 在 pickle_guard.py，仓库附带的十五条断言目前全部失败。要求先用 opcode 扫描，一旦出现 GLOBAL、STACK_GLOBAL、REDUCE、BUILD、INST、OBJ、NEWOBJ 或扩展 opcode 就拒绝，畸形数据同样报 ValueError，只允许基本标量、列表和字典。十五条过后，我会再跑 1200 组随机字节、20 路并发加载；用例不动，危险 opcode 名单不能写死成单个字符串。

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
