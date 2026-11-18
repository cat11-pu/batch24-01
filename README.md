# GSB Bugfix Task
## 题面
上传校验只看扩展名，MIME 和文件魔数不匹配也能过，polyglot 文件能同时被当图片和 HTML。mime_guard.py 的 validate 接收 (文件名, content_type, magic)，tests/test_mime_guard.py 15 个红。要修成扩展名、MIME 和魔数三者一致，文件名拒绝路径、空字节、双扩展和空值，非法组合抛 ValueError。15 个红测之外，验收还会用 1000 组随机上传和 32 线程并发校验，确认 MIME 不能混淆；不许改测试或硬编码文件名。边界至少覆盖扩展名/MIME/魔数不一致、路径、空字节、双扩展、空值和超长文件名。

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
