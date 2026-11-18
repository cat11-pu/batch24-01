# GSB Bugfix Task
## 题面
网关日志把请求原样打出来，password、token、api_key、Cookie 和银行卡号全进了日志文件，运维一搜就能拿到凭据。redact 在 log_redaction.py，仓库附带的十五条断言眼下全部报错。要求识别常见的敏感键值对并替换成固定占位符，Bearer 头和查询串里的 access_token 也要盖掉，卡号、SSN 这类数字串要脱敏，输出不能残留原值，非字符串输入先转成字符串再处理。交付前拿 1250 条随机日志、21 个线程同时脱敏；断言不许动，敏感关键词由调用方提供。

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
