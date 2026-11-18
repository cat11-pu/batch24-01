# GSB Bugfix Task
## 题面
PDF 上传要先做静态扫描：出现 JavaScript、JS、Launch、OpenAction、EmbeddedFile、RichMedia、AA、SubmitForm、ImportData、GoToR、XFA 这些主动内容就直接拒绝，空文件、非 bytes 和超大文件也不能进解析器。pdf_guard.py 的 scan_pdf 负责检查，现有十五条测试全部报错。data 得是 bytes，体积有上限；命中危险标记或类型不符都算失败，干净文件才放行。验收准备 1200 份随机 PDF、22 个线程一起扫描；断言文件不许动，体积上限由调用方定。

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
