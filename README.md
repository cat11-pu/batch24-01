# GSB Bugfix Task
## 题面
开放接口的 CORS 中间件把请求头里的 Origin 原样回写，还允许携带 Cookie，任何站点都能跨站读取用户数据。cors_guard.py 的 cors_headers 需要重写，仓库里十五条 param 用例眼下全红。Origin 必须和白名单逐字符相等，null、空串、子域后缀、协议或端口不一致、带认证信息、尾斜杠、fragment、查询串、换行和 NUL 一律抛错；通配符与 credentials 不能共存。十五条通过后，我会灌 1600 组随机 Origin、22 路并发比对响应头；用例不动，白名单从参数传入。

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
