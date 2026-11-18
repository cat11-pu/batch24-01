# GSB Bugfix Task
## 题面
凭据落库要能平滑升级：每次写入生成新的随机盐，用 PBKDF2 做慢哈希，存储串里记录算法、迭代次数和盐，验证时逐项解析并用固定节奏比较，迭代次数落后就标记为待升级，损坏的存储串一律判失败。password_vault.py 的 hash_password、verify_password、needs_rehash 要实现这套逻辑，套件十五条测试眼下全挂。密码得是字符串且长度受限；盐和迭代次数由参数给出。验收准备 1300 个随机密码、24 个线程一起哈希；断言文件保持原样，迭代下限交给调用方。

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
