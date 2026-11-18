# GSB Bugfix Task
## 题面
网关日志里出现两个请求被拼成一个的痕迹：前端送来的 Content-Length 和上游看到的 Transfer-Encoding 对不上，攻击者能借 CL.TE 或 TE.CL 把一段 payload 夹成队列里的下一个请求。仓库根目录的 smuggle_guard.py 负责判定，自带的 pytest 用例目前 15 条全部报错。判定逻辑要把同时带 CL 和 TE、CL 重复、TE 重复、TE 大小写或空白混淆、值里出现负号、加号、0x 前缀、逗号列表、尾部空白、CRLF 和 NUL 的情况统统拒掉，普通请求照常返回解析结果。写完后我会另起 800 组随机头、24 路并发灌进去，看还有没有请求能穿过；用例文件保持原样，头字段名也不允许硬编码。特别要盯 CL.TE、TE.CL、重复头、混淆 TE、负数和空头这些组合。

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
