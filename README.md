# GSB Bugfix Task
## 题面
网关要统一生成安全相关的响应字段：传输安全、防嵌入、CSP nonce、会话票据和跨域来源一起校验，明文请求不能下发传输安全字段，跨域来源必须命中允许集合，nonce 要够长且是 base64，max-age 和来源类型都要合法。build_headers 在 header_policy.py，仓库十五个用例现在全部失败。policy 和 request 必须是字典，冲突组合、非法值、空来源和类型错误都报错，合法配置返回可直接写进响应的字段表。验收拿 1400 组随机策略、22 个线程同时生成；断言保持原样，来源集合交给调用方。

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
