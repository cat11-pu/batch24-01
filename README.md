# GSB Bugfix Task
## 题面
文件隔离区要按策略放行：感染文件、加密文件、被禁扩展名一律进隔离；扫描状态未知或待定、大小超限、哈希格式不对、MIME 不在白名单、元数据缺失和策略为空都拒绝。file_quarantine.py 的 decide 负责判定，现有十五条测试全部报错。meta 和 policy 得是字典，size 非负，sha256 是十六进制，scan 只认 clean、infected、pending；返回 release 或 quarantine。交付前用 1400 份随机文件元数据、22 个线程压判定；断言文件保持原样，白名单和大小阈值交给调用方。

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
