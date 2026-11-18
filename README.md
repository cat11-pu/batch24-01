# GSB Bugfix Task
## 题面
配置中心把租户提交的 patch 递归合并进运行配置，__proto__、constructor、prototype 这类键能一路写进原型链，普通租户可以把自己抬成管理员。config_merge_guard.py 的 merge_config 要堵住这条链，现有一套十五个用例，跑起来全部红。patch 不是字典直接报错；任意层级出现危险键、空键或带控制字符的键都拒绝；已有键的类型不能互换——标量不能改字典、字典不能改标量、列表不能改字典。验收时我准备 1500 份随机配置、18 个线程一起合并；测试文件保持原样，危险键集合作为参数传进来。

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
