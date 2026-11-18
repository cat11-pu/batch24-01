# GSB Bugfix Task
## 题面
JSON Pointer 解析要防止越界和原型污染：指针必须以斜杠开头，~0 和 ~1 转义要合法，__proto__、constructor、prototype 段一律拒绝，数组下标不能带前导零、负数或越界，深度有上限，空指针只返回根文档。json_pointer.py 的 resolve 负责解析，现有十五条测试全部报错。document 得是字典或列表，pointer 得是字符串，max_depth 正数；类型不符、非法转义、危险段和越界都算失败。上线前用 1350 个随机指针、25 个线程压解析；断言文件保持原样，深度阈值交给调用方。

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
