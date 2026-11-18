# GSB Bugfix Task
## 题面
安全评审提了一个 OAuth 问题：授权码换 token 时 PKCE 校验形同虚设，plain 方式被接受，verifier 为空也能过，大小写变体也不拦，授权码一旦被截获就能直接兑换。校验函数 verify 位于 pkce_guard.py，随仓库提供的 15 条 pytest 断言目前全部失败。目标：只认 S256，challenge 与 verifier 必须严格对应，长度和字符集要合法，空值、换行、NUL、尾部空格、大小写差异全部拒绝。跑绿这 15 条后，我会再生成 512 组随机 PKCE 参数、8 路并发调用，确认不存在降级路径；用例文件不许改，challenge 也不能硬编码。plain、空 verifier、错 verifier、大小写、空值、换行和 NUL 是重点。

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
