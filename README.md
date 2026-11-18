# GSB Bugfix Task
## 题面
JWT 头里的 kid 被直接拼进密钥目录，传 ../../etc/passwd 就能让服务去读目录外的文件当密钥。jwt_kid_guard.py 的 resolve_key_path 要把住这道关，现成十五条测试现在无一通过。kid 必须逐个和调用方提供的密钥 ID 对齐，出现斜杠、反斜杠、上级引用、绝对路径、NUL、换行、空值、非字符串或超长值都抛 ValueError，解析结果必须落在密钥目录内。验收时准备 1350 个随机 kid、23 个线程并发解析；原有测试不能改，密钥 ID 集合由调用方提供。

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
