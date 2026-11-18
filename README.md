# GSB Bugfix Task
## 题面
XML 签名校验只看有没有 Signature 节点，攻击者可以包一层重复 ID 或把签名引用指向别的元素，验签通过但业务读到的是被替换的正文。xmlsig_guard.py 的 validate 是核心，tests/test_xmlsig_guard.py 15 个红。要修成只允许一个签名、引用必须命中受保护 ID、拒绝重复 ID 和包装层。15 个用例跑绿后，再用 1000 组随机 XML 和 32 线程并发校验，确认签名不能绕；不许改测试或硬编码 ID。边界至少覆盖重复 ID、包装层、空引用、外挂签名和实体。

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
