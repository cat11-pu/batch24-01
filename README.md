# GSB Bugfix Task
## 题面
后台管理页缺少防嵌入策略，攻击者用透明 iframe 盖住按钮，诱导管理员完成危险操作。frame_guard.py 的 frame_headers 需要生成防嵌入响应头，仓库里的用例一共十五个，目前全数失败。DENY 和 SAMEORIGIN 不能夹带来源；ALLOW-FROM 只接受调用方给的受信来源，且必须是加密地址，通配符、多个值、带路径、非标准端口、内嵌账号、末尾点、控制字符和空值都要抛 ValueError，返回值要能直接写进响应。完成后我拿 900 组随机模式和来源、14 路并发生成头来压；测试原样保留，受信来源由调用方提供。

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
