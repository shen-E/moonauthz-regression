# MoonAuthz-regression

MoonBit 编写的 API 对象级授权回归测试 CLI。它用 2 到 10 组身份先读取各自对象作为基线，再遍历所有不同身份之间的有序交叉访问，检查接口是否拒绝访问，以及响应中是否出现目标对象 ID 或敏感值。

支持 GET 读取和 POST、PUT、PATCH 写入检查。每次运行只访问配置中的 base_url；URL 模板必须是相对路径，最终请求会再次核对 origin，客户端不会自动跟随响应重定向。对象 ID 会作为单个 URL 路径段或 query 值进行百分号编码。凭据通过环境变量模板读取，不会写进报告或失败复现文件。

## 环境

- MoonBit 工具链
- Native 构建目标

## 本地演示

### 离线检查

    moon run --target native cmd/main -- validate examples/demo.json
    moon run --target native cmd/main -- plan examples/demo.json

`validate` 检查配置结构和认证环境变量是否可用，不会访问 API。`plan` 列出基线请求数、交叉身份组合和最终请求 URL，同样不发送请求；在运行写入配置前可用它检查预计触达的对象与清理流程。

运行时可用重复的 `--case` 参数选择指定跨身份用例，例如：

    moon run --target native cmd/main -- run examples/demo.json --case cross-A-to-B --case cross-B-to-A

用例名可从 `plan` 输出复制。筛选仍会先验证配置中的全部身份和自有对象基线，然后只发送所选跨身份请求；未知或重复的用例名会在发出请求前报错。

### 一键验收

安装 MoonBit 和 PowerShell 7 后，在仓库根目录运行：

    ./scripts/acceptance.ps1

脚本会先解析 MoonBit 依赖，再运行 moon check 和 moon test，然后自动启动安全版和漏洞版本地 API，使用同一配置执行测试，并核对基线、交叉访问结果、退出码和脱敏复现文件。完整输出保存在 artifacts/acceptance/<运行时间>/，包括两种模式的 JSON 报告、命令日志和 SUMMARY.md。脚本会检查生成的文件中没有演示令牌。

GitHub Actions 会在 push 和 pull request 时运行相同的验收流程。

### 手动读取演示

打开两个终端。先在终端 1 启动漏洞 API：

    moon run --target native cmd/demo -- --mode vulnerable

终端 2 设置演示令牌并运行同一配置：

    $env:MOONAUTHZ_TOKEN_A = "demo-token-a"
    $env:MOONAUTHZ_TOKEN_B = "demo-token-b"
    $env:MOONAUTHZ_TOKEN_C = "demo-token-c"
    moon run --target native cmd/main -- run examples/demo.json --out artifacts/vulnerable

漏洞版会让 A、B、C 之间的交叉读取成功，CLI 以退出码 1 报告越权，并为每个失败的身份组合生成脱敏 .http 复现请求。

停止终端 1 的服务，再启动安全 API：

    moon run --target native cmd/demo -- --mode safe

在终端 2 使用完全相同的配置：

    moon run --target native cmd/main -- run examples/demo.json --out artifacts/safe

安全版交叉访问返回 404 且没有泄露标记，CLI 以退出码 0 通过。每次运行都会输出逐用例结果和 report.json。

### 手动写入演示

使用相同的 API 服务和身份凭据，将配置换成 `examples/write-demo.json`。这个演示向对象发送 PATCH；安全版拒绝跨身份写入，漏洞版会修改对象字段。测试器会以对象所有者复读关键字段、执行 cleanup 恢复基线，并再次读取确认恢复完成。

写请求配置必须显式声明 `write_test_data: true`、`request.protected_json_pointers` 和 `cleanup`。请只使用可丢弃的隔离测试对象。cleanup 的 body 必须为每个受保护字段提供 `{{baseline:/pointer}}` 标记；清理失败或恢复后仍不一致时，运行退出 2 并在报告中记录错误。

## 配置格式

`examples/demo.json` 展示 GET 配置，`examples/write-demo.json` 展示受保护的 PATCH 流程。配置包含目标 base_url、请求方法和路径、公共请求头、2 到 10 组身份、各自对象 ID、身份请求头、基线成功状态、敏感 JSON Pointer 和跨身份拒绝状态。每个身份会与其他所有身份交叉测试；N 组身份会执行 N×(N−1) 条交叉用例。路径模板使用 `{{object_id}}`；请求头和写请求、cleanup 的 JSON 字符串值都支持 `${ENV:NAME}` 环境变量。写请求 body 还支持 `{{actor_name}}`、`{{actor_id}}` 和 `{{object_id}}`；cleanup body 还支持原始 JSON 值标记 `{{baseline:/pointer}}`。复现文件保留环境变量占位符，不包含替换后的实际值。

对象字段路径支持 JSON Pointer，包括嵌套对象和数组下标。默认 `leak_detection` 为 `json_pointer`：通过 `object_id_json_pointer`（默认 `/id`）定位对象 ID，并在自有对象基线中确认该字段与配置 ID 一致；敏感 JSON Pointer 的值也会按同一路径进行 JSON 值精确比较。这可避免短 ID 或常见子串造成误报。若接口返回非 JSON 响应，可将 `leak_detection` 设为 `substring`，对完整响应体执行子串扫描；这种模式可能因短字符串或常见文本产生误报。

`request.path` 中的 `{{object_id}}` 必须恰好出现一次，可放在路径或 query 值中。ID 中的斜杠、问号、井号、百分号、与号等字符会编码为一个组件，不能改变请求路径或参数结构。路径模板不能包含 fragment 或反斜杠。

基线 GET 必须返回配置的成功状态；结构化检测时对象 ID 路径缺失、对象 ID 与配置不符、敏感路径缺失或基线不是 JSON，运行作为配置/执行错误退出 2，不会把无效基线误报成通过。写请求除检查拒绝状态和响应泄露外，还会比较 owner 读回的受保护字段；每次跨身份写入后都会执行 cleanup 并复核这些字段是否恢复。

## 报告与退出码

- 0：所有自有对象基线有效，所有身份交叉访问都符合拒绝规则。
- 1：至少一个交叉访问状态不符合预期，或响应出现目标对象 ID/敏感值。
- 2：参数、配置、凭据、网络、基线或写入清理执行错误。

JSON 报告只记录请求头模板，不保存解析出的凭据或完整响应体。失败的 .http 文件使用环境变量占位符；若身份请求头没有环境变量模板，则值写成 <REDACTED>。写请求的复现文件还会包含测试请求体。默认输出目录 artifacts/ 已加入 .gitignore。

## 开发

    moon check --target native
    moon fmt

演示 API 只绑定 127.0.0.1:8095，使用内存中的固定订单数据，不访问外网。
