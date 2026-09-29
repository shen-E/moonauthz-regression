# MoonAuthz-regression

MoonBit 编写的 API 对象级授权回归测试 CLI。它用两组身份先读取各自对象作为基线，再交叉替换对象 ID，检查接口是否拒绝访问，以及响应中是否出现对方对象 ID 或敏感值。

首版只运行 GET 请求。每次运行只访问配置中的 base_url；URL 模板必须是相对路径，不会从响应重定向到其他地址。凭据通过环境变量模板读取，不会写进报告或失败复现文件。

## 环境

- MoonBit 工具链
- Native 构建目标

## 本地演示

### 一键验收

安装 MoonBit 和 PowerShell 7 后，在仓库根目录运行：

    ./scripts/acceptance.ps1

脚本会先解析 MoonBit 依赖，再运行 moon check --target native，然后自动启动安全版和漏洞版本地 API，使用同一配置执行测试，并核对基线、交叉访问结果、退出码和脱敏复现文件。完整输出保存在 artifacts/acceptance/<运行时间>/，包括两种模式的 JSON 报告、命令日志和 SUMMARY.md。脚本会检查生成的文件中没有演示令牌。

GitHub Actions 会在 push 和 pull request 时运行相同的验收流程。

### 手动演示

打开两个终端。先在终端 1 启动漏洞 API：

    moon run --target native cmd/demo -- --mode vulnerable

终端 2 设置演示令牌并运行同一配置：

    $env:MOONAUTHZ_TOKEN_A = "demo-token-a"
    $env:MOONAUTHZ_TOKEN_B = "demo-token-b"
    moon run --target native cmd/main -- run examples/demo.json --out artifacts/vulnerable

漏洞版会让 A、B 交叉读取成功，CLI 以退出码 1 报告越权，并在输出目录中生成脱敏 .http 复现请求。

停止终端 1 的服务，再启动安全 API：

    moon run --target native cmd/demo -- --mode safe

在终端 2 使用完全相同的配置：

    moon run --target native cmd/main -- run examples/demo.json --out artifacts/safe

安全版交叉访问返回 404 且没有泄露标记，CLI 以退出码 0 通过。每次运行都会输出逐用例结果和 report.json。

## 配置格式

examples/demo.json 展示完整配置。配置包含目标 base_url、GET 路径模板、公共请求头、两组身份、各自对象 ID、身份请求头、基线成功状态、敏感 JSON Pointer 和跨身份拒绝状态。路径模板使用 {{object_id}}；请求头中的 ${ENV:NAME} 从环境读取。

对象字段路径支持 JSON Pointer，包括嵌套对象和数组下标。基线请求必须返回配置的成功状态；敏感路径缺失或基线不是 JSON 时，运行作为配置/执行错误退出 2，不会把无效基线误报成通过。

## 报告与退出码

- 0：两个自有对象基线有效，所有交叉访问都符合拒绝规则。
- 1：至少一个交叉访问状态不符合预期，或响应出现目标对象 ID/敏感值。
- 2：参数、配置、凭据、网络或基线执行错误。

JSON 报告只记录请求头模板，不保存解析出的凭据或完整响应体。失败的 .http 文件使用环境变量占位符；若身份请求头没有环境变量模板，则值写成 <REDACTED>。默认输出目录 artifacts/ 已加入 .gitignore。

## 开发

    moon check --target native
    moon fmt

演示 API 只绑定 127.0.0.1:8095，使用内存中的固定订单数据，不访问外网。
