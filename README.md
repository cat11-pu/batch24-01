# GSB Bugfix Task
## 题面
支付网关要补状态机：授权、捕获、退款、作废各有前置状态，金额和币种必须对得上，重复捕获和超退都要拦住，并发下只能有一个捕获成功。apply_event 在 payment_state.py，十五个用例当前全部失败。state 必须是带 status、amount、currency 的字典，event 只认 capture、refund、void；非法状态、未知事件、负数金额、币种不符都抛 ValueError。改完我会用 1400 组随机事件序列、28 个线程并发跑；用例不能改，状态名和事件名不能写死成单个分支。

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
