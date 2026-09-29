///|
fn status_codes_text(codes : Array[Int]) -> String {
  let mut out = "["
  for i = 0; i < codes.length(); i = i + 1 {
    if i > 0 {
      out = out + ", "
    }
    out = out + codes[i].to_string()
  }
  out + "]"
}

///|
async fn send_get(url : String, headers : @http.Headers) -> (Int, String) {
  let (response, body) = @http.get(url, headers~)
  (response.code, body.text())
}

///|
fn marker_sources_in(body : String, markers : Array[Marker]) -> Array[String] {
  let found : Array[String] = []
  for marker in markers {
    if marker.value != "" && body.contains(marker.value) {
      found.push(marker.source)
    }
  }
  found
}

///|
fn create_case(
  case_name : String,
  identity : Identity,
  target_object : String,
  url : String,
  status : Int,
  expected : String,
  actual : String,
  passed : Bool,
  leaks : Array[String],
  display_headers : Map[String, String],
) -> TestCase {
  {
    case_name,
    identity: identity.name,
    target_object,
    url,
    status,
    expected,
    actual,
    passed,
    leaks,
    display_headers,
  }
}

///|
fn case_json(test_case : TestCase) -> Json {
  let headers : Map[String, Json] = Map([])
  for (name, value) in test_case.display_headers {
    headers[name] = Json::string(value)
  }
  let leaks : Array[Json] = []
  for leak in test_case.leaks {
    leaks.push(Json::string(leak))
  }
  Json::object({
    "case": Json::string(test_case.case_name),
    "identity": Json::string(test_case.identity),
    "target_object": Json::string(test_case.target_object),
    "method": Json::string("GET"),
    "url": Json::string(test_case.url),
    "status": Json::Json(test_case.status),
    "expected": Json::string(test_case.expected),
    "actual": Json::string(test_case.actual),
    "passed": Json::boolean(test_case.passed),
    "leaks": Json::array(leaks),
    "request_headers": Json::object(headers),
  })
}

///|
async fn write_report(
  output_dir : String,
  exit_code : Int,
  cases : Array[TestCase],
  setup_errors : Array[String],
) -> Unit {
  @fs.mkdir(output_dir, recursive=true, allow_exist=true)
  let case_values : Array[Json] = []
  for test_case in cases {
    case_values.push(case_json(test_case))
  }
  let errors : Array[Json] = []
  for message in setup_errors {
    errors.push(Json::string(message))
  }
  let status = if exit_code == 0 {
    "passed"
  } else if exit_code == 1 {
    "failed"
  } else {
    "error"
  }
  let report = Json::object({
    "tool": Json::string("moonauthz-regression"),
    "status": Json::string(status),
    "exit_code": Json::Json(exit_code),
    "cases": Json::array(case_values),
    "setup_errors": Json::array(errors),
  })
  @fs.write_file(output_dir + "/report.json", report.stringify(indent=2))
}

///|
async fn write_reproduction(
  output_dir : String,
  index : Int,
  test_case : TestCase,
) -> Unit {
  let mut text = "### Reproduce \{test_case.case_name}\n"
  text = text +
    "### Credentials are environment placeholders, never stored here.\n"
  text = text + "GET \{test_case.url} HTTP/1.1\n"
  for (name, value) in test_case.display_headers {
    text = text + "\{name}: \{value}\n"
  }
  text = text + "\n"
  @fs.write_file(output_dir + "/failure-\{index}.http", text)
}

///|
async fn run_config(config_path : String, output_dir : String) -> Int {
  let config_contents = @fs.read_file(config_path).text()
  let root = @json.parse(config_contents) catch {
    _ => raise CliError("配置不是有效 JSON: " + config_path)
  }
  let config = parse_config(root)
  @fs.mkdir(output_dir, recursive=true, allow_exist=true)
  let cases : Array[TestCase] = []
  let setup_errors : Array[String] = []
  let baseline_markers : Array[Array[Marker]] = [[], []]
  let baseline_ok = [false, false]

  // Owner reads prove that both test credentials and fixture objects are usable.
  for i = 0; i < config.identities.length(); i = i + 1 {
    let identity = config.identities[i]
    let url = build_url(config, identity.object_id)
    let headers = resolved_headers(config, identity)
    let (status, body) = send_get(url, headers)
    let status_ok = identity.baseline_statuses.contains(status)
    let mut actual = "HTTP \{status}"
    let mut passed = status_ok
    if !status_ok {
      actual = actual + "; 自有对象基线状态不在预期范围"
      setup_errors.push(
        "身份 \{identity.name} 的自有对象请求返回 HTTP \{status}",
      )
    } else {
      try {
        baseline_markers[i] = extract_markers(identity, body)
        baseline_ok[i] = true
      } catch {
        CliError(message) => {
          passed = false
          actual = actual + "; " + message
          setup_errors.push(message)
        }
      }
    }
    cases.push(
      create_case(
        "baseline-\{identity.name}",
        identity,
        identity.object_id,
        url,
        status,
        "HTTP \{status_codes_text(identity.baseline_statuses)} 且敏感字段可提取",
        actual,
        passed && baseline_ok[i],
        [],
        display_headers(config, identity),
      ),
    )
  }

  if setup_errors.length() > 0 {
    write_report(output_dir, 2, cases, setup_errors)
    for test_case in cases {
      let label = if test_case.passed { "PASS" } else { "ERROR" }
      println(
        "\{label} \{test_case.case_name}: expected \{test_case.expected}; actual \{test_case.actual}",
      )
    }
    println("报告已写入 \{output_dir}/report.json")
    return 2
  }

  let mut failure_count = 0
  for actor_index = 0; actor_index < 2; actor_index = actor_index + 1 {
    let target_index = 1 - actor_index
    let actor = config.identities[actor_index]
    let target = config.identities[target_index]
    let url = build_url(config, target.object_id)
    let headers = resolved_headers(config, actor)
    let (status, body) = send_get(url, headers)
    let leaks = marker_sources_in(body, baseline_markers[target_index])
    let denied = config.denied_statuses.contains(status)
    let passed = denied && leaks.length() == 0
    let actual = if leaks.length() > 0 {
      "HTTP \{status}; 响应包含受保护标记: " +
      join_strings(leaks, ", ")
    } else if denied {
      "HTTP \{status}; 未发现受保护标记"
    } else {
      "HTTP \{status}; 状态码不属于拒绝集合"
    }
    let test_case = create_case(
      "cross-\{actor.name}-to-\{target.name}",
      actor,
      target.object_id,
      url,
      status,
      "HTTP \{status_codes_text(config.denied_statuses)} 且不含目标对象 ID/敏感值",
      actual,
      passed,
      leaks,
      display_headers(config, actor),
    )
    cases.push(test_case)
    if !passed {
      write_reproduction(output_dir, failure_count + 1, test_case)
      failure_count = failure_count + 1
    }
  }

  let exit_code = if failure_count == 0 { 0 } else { 1 }
  write_report(output_dir, exit_code, cases, setup_errors)
  for test_case in cases {
    let label = if test_case.passed { "PASS" } else { "FAIL" }
    println(
      "\{label} \{test_case.case_name}: expected \{test_case.expected}; actual \{test_case.actual}",
    )
  }
  if failure_count > 0 {
    println("已保存 \{failure_count} 个脱敏复现请求到 \{output_dir}")
  }
  println("报告已写入 \{output_dir}/report.json")
  exit_code
}

///|
fn join_strings(values : Array[String], separator : String) -> String {
  let mut out = ""
  for i = 0; i < values.length(); i = i + 1 {
    if i > 0 {
      out = out + separator
    }
    out = out + values[i]
  }
  out
}

///|
fn parse_run_arguments(args : Array[String]) -> (String, String) raise CliError {
  if args.length() < 2 {
    raise CliError(
      "用法: moonauthz-regression run <config.json> [--out <目录>]",
    )
  }
  let config_path = args[1]
  let mut output_dir = "artifacts"
  let mut index = 2
  while index < args.length() {
    if args[index] == "--out" && index + 1 < args.length() {
      output_dir = args[index + 1]
      index = index + 2
    } else {
      raise CliError("未知或不完整参数: " + args[index])
    }
  }
  (config_path, output_dir)
}

///|
async fn run_cli_inner(args : Array[String]) -> Int {
  if args.length() == 0 || args[0] == "--help" || args[0] == "help" {
    println("用法: moonauthz-regression run <config.json> [--out <目录>]")
    return 0
  }
  if args[0] != "run" {
    raise CliError("未知子命令: " + args[0])
  }
  let (config_path, output_dir) = parse_run_arguments(args)
  run_config(config_path, output_dir)
}

///|
pub async fn run_cli(raw_args : Array[String]) -> Int {
  let args : Array[String] = []
  for index = 1; index < raw_args.length(); index = index + 1 {
    args.push(raw_args[index])
  }
  run_cli_inner(args) catch {
    CliError(message) => {
      println("ERROR: \{message}")
      println("退出码: 2")
      2
    }
    err => {
      println("ERROR: 网络、文件或 JSON 处理失败: \{err}")
      println("退出码: 2")
      2
    }
  }
}
