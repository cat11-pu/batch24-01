# GSB Bugfix Task
## 题面
网关信任 X-HTTP-Method-Override，TRACE、CONNECT 和大小写变体都能透传到后端，方法白名单等于摆设。method_guard.py 里的 resolve_method 要重做，测试套件一共十五个用例，当前全挂。方法名必须精确落在调用方给的集合里；前后空白、换行、NUL、小写写法、空串、数字类型都算非法，覆盖头也只能从同一集合取值且不能重复，出错统一抛 ValueError。最后用 1300 个随机方法名和覆盖头、22 个线程同时解析来验；断言文件保持原样，可用方法集合通过参数传进来。

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
