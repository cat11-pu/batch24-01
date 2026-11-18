# GSB Bugfix Task
## 题面
JWT 的 kid 直接拼路径加载密钥，../../etc/passwd 和绝对路径能读任意文件。jwt_kid_guard.py 的 validate 是核心，tests/test_jwt_kid_guard.py 15 个红。要修成 kid 只允许字母数字和短横线、必须命中密钥目录、拒绝路径分隔符、空字节和超长值。15 个用例跑绿后，再用 1000 组随机 kid 和 32 线程并发校验，确认不能目录穿越；不许改测试或硬编码 kid。边界至少覆盖 ../、绝对路径、反斜杠、空字节、空值和超长。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：身份认证
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
