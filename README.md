# GSB Bugfix Task
## 题面
优惠券并发兑换没有原子锁，同一张券能被两个请求同时核销。coupon_guard.py 的 validate 接收 (state, count, now)，tests/test_coupon_guard.py 15 个红。要修成状态机只允许未使用到已使用一次、并发只成功一个、过期和负数拒绝。15 个测试通过后，再用 1000 组随机状态和 32 线程并发校验，确认不能重复核销；不许改测试或硬编码状态。边界至少覆盖已使用、计数为 0/负数、过期、负时间、布尔、浮点和 None。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
