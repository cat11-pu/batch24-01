# GSB Bugfix Task
## 题面
JWT 校验要支持密钥轮换但不能被降级：只认 HS256，kid 必须命中密钥表且不能带路径，签名要用常量时间比较，exp、nbf、iat、iss、aud 全部校验，留六十秒时钟偏移，撤销列表里的 jti 直接拒绝。verify 在 jwt_rotation.py，十五个用例现在全红。token 必须是非空字符串，密钥表、签发方、受众和撤销集合由调用方传入；畸形 token、未知 kid、签名错误都算失败。改完我用 1300 个随机 token、26 个线程并发校验；测试不能改，密钥轮换不能写死单个 key。

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
