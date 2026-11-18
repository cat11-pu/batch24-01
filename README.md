# GSB Bugfix Task
## 题面
文件路径校验只按 ASCII 的 / 和 .. 判断，全角斜杠、division slash、fraction slash 和 bidi 控制字符能绕过。unicode_guard.py 的 validate 是核心，tests/test_unicode_guard.py 15 个红。要修成 NFKC 归一化后再检查斜杠和点段，拒绝全角/数学斜杠、零宽字符、bidi 控制和双重编码。15 个测试通过后，再跑 1000 组随机路径和 32 线程并发校验，确认 Unicode 不能绕过；不许改测试或硬编码字符。边界至少覆盖全角斜杠、U+2215、U+2044、U+29F8、零宽字符、bidi 和双重编码。

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
