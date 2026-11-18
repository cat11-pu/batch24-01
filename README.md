# GSB Bugfix Task
## 题面
接口错误直接回显异常栈、SQL、文件路径和内网地址，攻击者能拿这些信息继续打。error_guard.py 的 validate 是核心，tests/test_error_guard.py 15 个红。要修成对外错误只保留通用文案和错误码，拒绝栈帧、SQL、绝对路径、内网 IP、密钥片段和超长消息。15 个用例跑绿后，再用 1000 组随机错误和 32 线程并发校验，确认没有泄漏；不许改测试或硬编码文案。边界至少覆盖栈帧、SQL、绝对路径、内网 IP、token、空值和超长。

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
