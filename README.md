# GSB Bugfix Task
## 题面
反向代理同时接受 Content-Length 和 Transfer-Encoding，CL.TE/TE.CL 走私能绕过鉴权。smuggling_guard.py 的 validate 接收头列表，tests/test_smuggling_guard.py 15 个红。要修成拒绝同时出现 CL/TE、重复 CL、混淆 TE、负值和控制字符。15 个用例跑绿后，再用 1000 组随机头和 32 线程并发校验，确认不能走私；不许改测试或硬编码头名。边界至少覆盖 CL.TE、TE.CL、重复 CL、混淆 TE、负值和空头。

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
