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
fn http_method(verb : String) -> @http.RequestMethod {
  match verb {
    "GET" => @http.Get
    "POST" => @http.Post
    "PUT" => @http.Put
    "PATCH" => @http.Patch
    _ => @http.Get
  }
}

///|
async fn send_request(
  url : String,
  verb : String,
  headers : @http.Headers,
  body : String,
) -> (Int, String) {
  let (response, response_body) = @http.request(
    url,
    http_method(verb),
    headers,
    body,
  )
  (response.code, response_body.text())
}

///|
async fn try_send_get(
  url : String,
  headers : @http.Headers,
) -> (Int, String, Bool) {
  try {
    let (status, body) = send_get(url, headers)
    (status, body, false)
  } catch {
    _ => (0, "", true)
  }
}

///|
async fn try_send_request(
  url : String,
  verb : String,
  headers : @http.Headers,
  body : String,
) -> (Int, String, Bool) {
  try {
    let (status, response_body) = send_request(url, verb, headers, body)
    (status, response_body, false)
  } catch {
    _ => (0, "", true)
  }
}

///|
fn marker_sources_in(
  body : String,
  markers : Array[Marker],
  leak_detection : String,
) -> Array[String] {
  let found : Array[String] = []
  if leak_detection == "substring" {
    for marker in markers {
      if marker.value != "" && body.contains(marker.value) {
        found.push(marker.source)
      }
    }
    return found
  }
  let json = @json.parse(body) catch { _ => return found }
  for marker in markers {
    match (marker.pointer, marker.json_value) {
      (Some(pointer), Some(baseline_value)) =>
        match json_pointer(json, pointer) {
          Some(value) if Json::equal(value, baseline_value) =>
            found.push(marker.source)
          _ => ()
        }
      _ => ()
    }
  }
  found
}

///|
fn url_origin(url : String) -> String? {
  guard url.find("://") is Some(scheme_end) else { return None }
  let authority_start = scheme_end + 3
  let remainder = url[authority_start:]
  let authority_end = match remainder.find("/") {
    Some(index) => index
    None => remainder.length()
  }
  if authority_end == 0 {
    None
  } else {
    Some(url[:authority_start + authority_end].to_owned())
  }
}

///|
fn ensure_same_origin(config : AppConfig, url : String) -> Unit raise CliError {
  match (url_origin(config.base_url), url_origin(url)) {
    (Some(expected), Some(actual)) if expected == actual => ()
    _ => raise CliError("最终请求 URL 的 origin 与 base_url 不一致")
  }
}

///|
fn create_case(
  case_name : String,
  identity : Identity,
  target_object : String,
  verb : String,
  url : String,
  request_body : String,
  status : Int,
  expected : String,
  actual : String,
  passed : Bool,
  leaks : Array[String],
  state_changes : Array[String],
  cleanup_status : Int?,
  display_headers : Map[String, String],
) -> TestCase {
  {
    case_name,
    identity: identity.name,
    target_object,
    verb,
    url,
    request_body,
    status,
    expected,
    actual,
    passed,
    leaks,
    state_changes,
    cleanup_status,
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
    "method": Json::string(test_case.verb),
    "url": Json::string(test_case.url),
    "status": Json::Json(test_case.status),
    "expected": Json::string(test_case.expected),
    "actual": Json::string(test_case.actual),
    "passed": Json::boolean(test_case.passed),
    "leaks": Json::array(leaks),
    "state_changes": Json::array(test_case.state_changes.map(Json::string)),
    "cleanup_status": match test_case.cleanup_status {
      Some(status) => Json::Json(status)
      None => Json::null()
    },
    "request_headers": Json::object(headers),
  })
}

///|
async fn write_report(
  output_dir : String,
  exit_code : Int,
  cases : Array[TestCase],
  setup_errors : Array[String],
  execution_errors : Array[String],
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
  let runtime_errors : Array[Json] = []
  for message in execution_errors {
    runtime_errors.push(Json::string(message))
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
    "execution_errors": Json::array(runtime_errors),
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
  text = text + "\{test_case.verb} \{test_case.url} HTTP/1.1\n"
  for (name, value) in test_case.display_headers {
    text = text + "\{name}: \{value}\n"
  }
  text = text + "\n"
  if test_case.verb != "GET" {
    text = text + test_case.request_body + "\n"
  }
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
  let execution_errors : Array[String] = []
  let baseline_markers : Array[Array[Marker]] = []
  let baseline_states : Array[Array[FieldSnapshot]] = []
  let baseline_ok : Array[Bool] = []
  for i = 0; i < config.identities.length(); i = i + 1 {
    baseline_markers.push([])
    baseline_states.push([])
    baseline_ok.push(false)
  }

  // Owner reads prove that every test credential and fixture object is usable.
  for i = 0; i < config.identities.length(); i = i + 1 {
    let identity = config.identities[i]
    let url = build_url(config, identity.object_id)
    ensure_same_origin(config, url)
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
        baseline_markers[i] = extract_markers(config, identity, body)
        if config.request_method != "GET" {
          baseline_states[i] = extract_state(body, config.protected_pointers)
        }
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
        "GET",
        url,
        "",
        status,
        "HTTP \{status_codes_text(identity.baseline_statuses)} 且敏感字段可提取",
        actual,
        passed && baseline_ok[i],
        [],
        [],
        None,
        display_headers(config, identity),
      ),
    )
  }

  if setup_errors.length() > 0 {
    write_report(output_dir, 2, cases, setup_errors, execution_errors)
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
  for actor_index = 0
      actor_index < config.identities.length()
      actor_index = actor_index + 1 {
    for target_index = 0
        target_index < config.identities.length()
        target_index = target_index + 1 {
      if actor_index != target_index {
        let actor = config.identities[actor_index]
        let target = config.identities[target_index]
        let url = build_url(config, target.object_id)
        ensure_same_origin(config, url)
        let request_body = if config.request_method == "GET" {
          ""
        } else {
          render_write_body(config, actor, target)
        }
        let headers = resolved_headers(config, actor)
        let (status, body, request_failed) = try_send_request(
          url,
          config.request_method,
          headers,
          request_body,
        )
        let state_changes : Array[String] = []
        let mut cleanup_status : Int? = None
        let mut case_execution_ok = !request_failed
        if request_failed {
          execution_errors.push(
            "身份 \{actor.name} 的跨对象请求失败；仍会尝试执行清理",
          )
        }
        let leaks = marker_sources_in(
          body,
          baseline_markers[target_index],
          config.leak_detection,
        )
        let denied = config.denied_statuses.contains(status)
        if config.request_method != "GET" {
          let target_url = build_url(config, target.object_id)
          ensure_same_origin(config, target_url)
          let owner_headers = resolved_headers(config, target)
          let (owner_status, owner_body, owner_read_failed) = try_send_get(
            target_url, owner_headers,
          )
          if owner_read_failed ||
            !target.baseline_statuses.contains(owner_status) {
            case_execution_ok = false
            execution_errors.push(
              "身份 \{target.name} 写入后无法读取自有对象: HTTP \{owner_status}",
            )
          } else {
            try {
              let changed = changed_state_fields(
                owner_body,
                baseline_states[target_index],
              )
              for pointer in changed {
                state_changes.push(pointer)
              }
            } catch {
              CliError(message) => {
                case_execution_ok = false
                execution_errors.push(message)
              }
            }
          }

          let cleanup = match config.cleanup {
            Some(value) => value
            None => raise CliError("写请求缺少清理配置")
          }
          let cleanup_url = config.base_url +
            replace_all(
              cleanup.path_template,
              "{{object_id}}",
              url_component_encode(target.object_id),
            )
          ensure_same_origin(config, cleanup_url)
          let cleanup_body = render_cleanup_body(
            cleanup,
            target,
            target,
            baseline_states[target_index],
          )
          let cleanup_headers = resolved_headers(config, target)
          let (cleanup_result, _, cleanup_failed) = try_send_request(
            cleanup_url,
            cleanup.verb,
            cleanup_headers,
            cleanup_body,
          )
          if cleanup_failed {
            case_execution_ok = false
            execution_errors.push(
              "身份 \{target.name} 的清理请求未完成",
            )
          } else {
            cleanup_status = Some(cleanup_result)
          }
          if !cleanup_failed &&
            !cleanup.success_statuses.contains(cleanup_result) {
            case_execution_ok = false
            execution_errors.push(
              "身份 \{target.name} 清理请求返回未配置的 HTTP \{cleanup_result}",
            )
          }

          let (verify_status, verify_body, verify_failed) = try_send_get(
            target_url, owner_headers,
          )
          if verify_failed || !target.baseline_statuses.contains(verify_status) {
            case_execution_ok = false
            execution_errors.push(
              "身份 \{target.name} 清理后无法复核自有对象: HTTP \{verify_status}",
            )
          } else {
            try {
              let remaining = changed_state_fields(
                verify_body,
                baseline_states[target_index],
              )
              for pointer in remaining {
                state_changes.push("cleanup:" + pointer)
                case_execution_ok = false
                execution_errors.push(
                  "身份 \{target.name} 清理后字段仍与基线不同: " +
                  pointer,
                )
              }
            } catch {
              CliError(message) => {
                case_execution_ok = false
                execution_errors.push(message)
              }
            }
          }
        }
        let passed = denied &&
          leaks.length() == 0 &&
          state_changes.length() == 0 &&
          case_execution_ok
        let mut actual = "HTTP \{status}"
        if leaks.length() > 0 {
          actual = actual +
            "; 响应包含受保护标记: " +
            join_strings(leaks, ", ")
        } else {
          actual = actual + "; 未发现受保护标记"
        }
        if !denied {
          actual = actual + "; 状态码不属于拒绝集合"
        }
        if state_changes.length() > 0 {
          actual = actual +
            "; 对象状态变化: " +
            join_strings(state_changes, ", ")
        }
        if cleanup_status is Some(cleanup_result) {
          actual = actual + "; 清理 HTTP \{cleanup_result}"
        }
        let test_case = create_case(
          "cross-\{actor.name}-to-\{target.name}",
          actor,
          target.object_id,
          config.request_method,
          url,
          request_body,
          status,
          if config.request_method == "GET" {
            "HTTP \{status_codes_text(config.denied_statuses)} 且不含目标对象 ID/敏感值"
          } else {
            "HTTP \{status_codes_text(config.denied_statuses)}，对象状态不变且清理后恢复基线"
          },
          actual,
          passed,
          leaks,
          state_changes,
          cleanup_status,
          display_headers(config, actor),
        )
        cases.push(test_case)
        if !passed {
          write_reproduction(output_dir, failure_count + 1, test_case)
          failure_count = failure_count + 1
        }
      }
    }
  }

  let exit_code = if execution_errors.length() > 0 {
    2
  } else if failure_count == 0 {
    0
  } else {
    1
  }
  write_report(output_dir, exit_code, cases, setup_errors, execution_errors)
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
