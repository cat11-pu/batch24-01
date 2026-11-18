# GSB Bugfix Task
## 题面
内省接口返回的内容不能照单全收：active 必须为真，exp 和 iat 要是整数且先后合理，aud 里得有当前调用方，iss 必须对得上，scope 要覆盖所需权限，token_type 只认 Bearer，sub 不能为空，字段类型不对或自相矛盾都要拒绝。oauth_introspection.py 的 validate 负责判定，套件十五条测试现在全挂。response 得是字典，当前时间、调用方标识、签发方和所需 scope 作为参数传入；非法内省结果统一报错。上线前用 1400 条随机内省响应做批量校验，线程数 23；断言文件保持原样，签发方和调用方交给使用方指定。

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
