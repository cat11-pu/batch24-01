# GSB Bugfix Task
## 题面
YAML 加载直接 yaml.load，!!python/object、!!python/name 和锚点别名能执行代码。yaml_guard.py 的 validate 是核心，tests/test_yaml_guard.py 15 个红。要修成只允许安全标量/列表/字典，拒绝 python 标签、对象构造、锚点别名和超深嵌套。15 个红测之后，再用 1000 组随机 YAML 和 32 线程并发校验，确认不能执行对象；不许改测试或硬编码标签。边界至少覆盖 python/object、python/name、锚点、别名、深嵌套和空值。

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
