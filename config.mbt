///|
priv suberror CliError {
  CliError(String)
}

///|
priv struct Identity {
  name : String
  object_id : String
  headers : Map[String, String]
  baseline_statuses : Array[Int]
  sensitive_pointers : Array[String]
}

///|
priv struct AppConfig {
  base_url : String
  path_template : String
  request_method : String
  request_body : String?
  object_id_pointer : String
  leak_detection : String
  protected_pointers : Array[String]
  cleanup : CleanupConfig?
  common_headers : Map[String, String]
  identities : Array[Identity]
  denied_statuses : Array[Int]
}

///|
priv struct CleanupConfig {
  verb : String
  path_template : String
  body_template : String
  success_statuses : Array[Int]
}

///|
priv struct FieldSnapshot {
  pointer : String
  value : Json
}

///|
priv struct Marker {
  source : String
  value : String
  pointer : String?
  json_value : Json?
}

///|
priv struct TestCase {
  case_name : String
  identity : String
  target_object : String
  verb : String
  url : String
  request_body : String
  status : Int
  expected : String
  actual : String
  passed : Bool
  leaks : Array[String]
  state_changes : Array[String]
  cleanup_status : Int?
  display_headers : Map[String, String]
}

///|
fn object_field(value : Json, key : String) -> Json? {
  match value {
    Json::Object(fields) => fields.get(key)
    _ => None
  }
}

///|
fn required_field(value : Json, key : String) -> Json raise CliError {
  match object_field(value, key) {
    Some(field) => field
    None => raise CliError("缺少必填字段: " + key)
  }
}

///|
fn required_string(value : Json, key : String) -> String raise CliError {
  match required_field(value, key) {
    Json::String(text) => text
    _ => raise CliError("字段必须是字符串: " + key)
  }
}

///|
fn optional_string(
  value : Json,
  key : String,
  default : String,
) -> String raise CliError {
  match object_field(value, key) {
    None => default
    Some(Json::String(text)) => text
    _ => raise CliError("字段必须是字符串: " + key)
  }
}

///|
fn string_map(
  value : Json?,
  field_name : String,
) -> Map[String, String] raise CliError {
  let out : Map[String, String] = Map([])
  match value {
    None => ()
    Some(Json::Object(fields)) =>
      for (key, item) in fields {
        match item {
          Json::String(text) => out[key] = text
          _ =>
            raise CliError(
              "请求头值必须是字符串: " + field_name + "." + key,
            )
        }
      }
    _ => raise CliError("请求头必须是 JSON 对象: " + field_name)
  }
  out
}

///|
fn int_array(value : Json, field_name : String) -> Array[Int] raise CliError {
  match value {
    Json::Array(items) => {
      let out : Array[Int] = []
      for item in items {
        match item {
          Json::Number(number, ..) => {
            let code = number.to_int()
            if code < 100 || code > 599 || code.to_double() != number {
              raise CliError(
                "HTTP 状态码必须是 100 到 599 的整数: " + field_name,
              )
            }
            out.push(code)
          }
          _ =>
            raise CliError("状态码数组只能包含数字: " + field_name)
        }
      }
      if out.length() == 0 {
        raise CliError("状态码数组不能为空: " + field_name)
      }
      out
    }
    _ => raise CliError("字段必须是状态码数组: " + field_name)
  }
}

///|
fn string_array(
  value : Json?,
  field_name : String,
) -> Array[String] raise CliError {
  match value {
    None => []
    Some(Json::Array(items)) => {
      let out : Array[String] = []
      for item in items {
        match item {
          Json::String(text) => out.push(text)
          _ =>
            raise CliError("字段数组只能包含字符串: " + field_name)
        }
      }
      out
    }
    _ => raise CliError("字段必须是字符串数组: " + field_name)
  }
}

///|
fn required_boolean(value : Json, key : String) -> Bool raise CliError {
  match required_field(value, key) {
    Json::True => true
    Json::False => false
    _ => raise CliError("字段必须是布尔值: " + key)
  }
}

///|
fn decode_pointer_segment(segment : String) -> String {
  let mut decoded = segment
  while decoded.contains("~1") {
    decoded = decoded.replace(old="~1", new="/")
  }
  while decoded.contains("~0") {
    decoded = decoded.replace(old="~0", new="~")
  }
  decoded
}

///|
fn parse_array_index(segment : StringView) -> Int? {
  if segment.length() == 0 {
    return None
  }
  let mut value = 0
  for ch in segment {
    let digit = match ch {
      '0' => 0
      '1' => 1
      '2' => 2
      '3' => 3
      '4' => 4
      '5' => 5
      '6' => 6
      '7' => 7
      '8' => 8
      '9' => 9
      _ => return None
    }
    value = value * 10 + digit
  }
  Some(value)
}

///|
fn json_pointer(root : Json, pointer : String) -> Json? {
  if pointer == "" {
    return Some(root)
  }
  if !pointer.has_prefix("/") {
    return None
  }
  let mut current = root
  let mut first = true
  for part in pointer.split("/") {
    if first {
      first = false
      continue
    }
    let key = decode_pointer_segment(part.to_owned())
    current = match current {
      Json::Object(fields) =>
        match fields.get(key) {
          Some(value) => value
          None => return None
        }
      Json::Array(items) =>
        match parse_array_index(part) {
          Some(index) if index >= 0 && index < items.length() => items[index]
          _ => return None
        }
      _ => return None
    }
  }
  Some(current)
}

///|
fn json_marker(value : Json) -> String? {
  match value {
    Json::Null => None
    Json::String(text) => if text == "" { None } else { Some(text) }
    _ => Some(value.stringify())
  }
}

///|
fn parse_config(root : Json) -> AppConfig raise CliError {
  let base_url = required_string(root, "base_url")
  if !(base_url.has_prefix("http://") || base_url.has_prefix("https://")) {
    raise CliError("base_url 必须以 http:// 或 https:// 开头")
  }
  if base_url.contains("?") || base_url.contains("#") {
    raise CliError("base_url 不能包含 query 或 fragment")
  }
  if base_url.contains("\\") ||
    base_url.contains(" ") ||
    base_url.contains("\r") ||
    base_url.contains("\n") ||
    base_url.contains("\t") {
    raise CliError("base_url 不能包含反斜杠、空格或控制字符")
  }
  let mut normalized_base = base_url
  while normalized_base.has_suffix("/") {
    normalized_base = normalized_base[:normalized_base.length() - 1].to_owned()
  }

  let request = required_field(root, "request")
  let method_text = optional_string(request, "method", "GET")
  if !is_supported_method(method_text) {
    raise CliError("request.method 只能是 GET、POST、PUT 或 PATCH")
  }
  let body_template = optional_string(request, "body", "")
  if method_text == "GET" && body_template != "" {
    raise CliError("GET 请求不能配置 request.body")
  }
  if method_text != "GET" && body_template == "" {
    raise CliError("写请求必须配置 JSON request.body")
  }
  let path_template = required_string(request, "path")
  validate_path_template(path_template, "request.path")
  let leak_detection = optional_string(root, "leak_detection", "json_pointer")
  if leak_detection != "json_pointer" && leak_detection != "substring" {
    raise CliError("leak_detection 只能是 json_pointer 或 substring")
  }
  let object_id_pointer = optional_string(root, "object_id_json_pointer", "/id")
  if leak_detection == "json_pointer" && !is_json_pointer(object_id_pointer) {
    raise CliError("object_id_json_pointer 必须是有效 JSON Pointer")
  }
  let common_headers = string_map(
    object_field(request, "headers"),
    "request.headers",
  )

  let protected_pointers = string_array(
    object_field(request, "protected_json_pointers"),
    "request.protected_json_pointers",
  )
  for pointer in protected_pointers {
    if !is_json_pointer(pointer) {
      raise CliError(
        "受保护状态路径必须是有效 JSON Pointer: " + pointer,
      )
    }
  }
  let cleanup = if method_text == "GET" {
    if object_field(root, "cleanup") is Some(_) {
      raise CliError("GET 用例不能配置 cleanup")
    }
    None
  } else {
    if required_boolean(root, "write_test_data") != true {
      raise CliError("写请求必须显式设置 write_test_data: true")
    }
    if protected_pointers.length() == 0 {
      raise CliError(
        "写请求必须配置 request.protected_json_pointers，便于验证对象状态",
      )
    }
    let sample_request_body = render_body_tokens(
      body_template, "sample-actor", "sample-object", "sample-id",
    )
    if sample_request_body.contains("{{") {
      raise CliError("request.body 包含不支持的模板标记")
    }
    ignore(
      @json.parse(sample_request_body) catch {
        _ => raise CliError("request.body 模板展开后必须是有效 JSON")
      },
    )
    Some(parse_cleanup(required_field(root, "cleanup"), protected_pointers))
  }

  let raw_identities = required_field(root, "identities")
  let identities = match raw_identities {
    Json::Array(items) => {
      if items.length() < 2 || items.length() > 10 {
        raise CliError(
          "必须配置 2 到 10 组测试身份，以限制交叉请求数量",
        )
      }
      let out : Array[Identity] = []
      for item in items {
        let name = required_string(item, "name")
        if name == "" {
          raise CliError("身份名称不能为空")
        }
        let object_id = required_string(item, "object_id")
        if object_id == "" {
          raise CliError("object_id 不能为空: " + name)
        }
        let headers = string_map(
          object_field(item, "headers"),
          "identities." + name + ".headers",
        )
        let baseline_statuses = match object_field(item, "baseline_statuses") {
          None => [200]
          Some(statuses) =>
            int_array(statuses, "identities." + name + ".baseline_statuses")
        }
        let sensitive_pointers = string_array(
          object_field(item, "sensitive_json_pointers"),
          "identities." + name + ".sensitive_json_pointers",
        )
        for pointer in sensitive_pointers {
          if !is_json_pointer(pointer) {
            raise CliError(
              "敏感字段路径必须是有效 JSON Pointer: " + pointer,
            )
          }
        }
        out.push({
          name,
          object_id,
          headers,
          baseline_statuses,
          sensitive_pointers,
        })
      }
      for i = 0; i < out.length(); i = i + 1 {
        for j = 0; j < i; j = j + 1 {
          if out[i].name == out[j].name {
            raise CliError("身份名称必须各不相同: " + out[i].name)
          }
          if out[i].object_id == out[j].object_id {
            raise CliError("对象 ID 必须各不相同: " + out[i].object_id)
          }
        }
      }
      out
    }
    _ => raise CliError("identities 必须是 JSON 数组")
  }

  let denied_statuses = int_array(
    required_field(root, "denied_statuses"),
    "denied_statuses",
  )
  {
    base_url: normalized_base,
    path_template,
    request_method: method_text,
    request_body: if body_template == "" {
      None
    } else {
      Some(body_template)
    },
    object_id_pointer,
    leak_detection,
    protected_pointers,
    cleanup,
    common_headers,
    identities,
    denied_statuses,
  }
}

///|
fn is_supported_method(verb : String) -> Bool {
  verb == "GET" || verb == "POST" || verb == "PUT" || verb == "PATCH"
}

///|
fn validate_path_template(
  path : String,
  field_name : String,
) -> Unit raise CliError {
  if !path.has_prefix("/") || path.has_prefix("//") {
    raise CliError(
      field_name + " 必须是以单个 / 开头的相对路径模板",
    )
  }
  if count_occurrences(path, "{{object_id}}") != 1 {
    raise CliError(field_name + " 必须且只能包含一个 {{object_id}}")
  }
  if path.contains("#") ||
    path.contains("\\") ||
    path.contains("\r") ||
    path.contains("\n") ||
    path.contains("\t") {
    raise CliError(
      field_name + " 不能包含 fragment、反斜杠或控制字符",
    )
  }
}

///|
fn parse_cleanup(
  value : Json,
  protected_pointers : Array[String],
) -> CleanupConfig raise CliError {
  let verb = required_string(value, "method")
  if verb != "POST" && verb != "PUT" && verb != "PATCH" {
    raise CliError("cleanup.method 只能是 POST、PUT 或 PATCH")
  }
  let path_template = required_string(value, "path")
  validate_path_template(path_template, "cleanup.path")
  let body_template = required_string(value, "body")
  if body_template == "" {
    raise CliError("cleanup.body 不能为空")
  }
  let success_statuses = match object_field(value, "success_statuses") {
    None => [200, 204]
    Some(statuses) => int_array(statuses, "cleanup.success_statuses")
  }
  let mut sample_body = body_template
  for pointer in protected_pointers {
    let marker = "{{baseline:" + pointer + "}}"
    if !sample_body.contains(marker) {
      raise CliError("cleanup.body 必须恢复受保护字段: " + pointer)
    }
    sample_body = replace_all(
      sample_body,
      marker,
      Json::string("baseline").stringify(),
    )
  }
  sample_body = render_body_tokens(
    sample_body, "sample-actor", "sample-object", "sample-id",
  )
  if sample_body.contains("{{") {
    raise CliError("cleanup.body 包含不支持的模板标记")
  }
  ignore(
    @json.parse(sample_body) catch {
      _ => raise CliError("cleanup.body 模板展开后必须是有效 JSON")
    },
  )
  { verb, path_template, body_template, success_statuses, }
}

///|
fn count_occurrences(input : String, pattern : String) -> Int {
  let mut remaining = input
  let mut count = 0
  while remaining.find(pattern) is Some(index) {
    count = count + 1
    remaining = remaining[index + pattern.length():].to_owned()
  }
  count
}

///|
fn is_json_pointer(pointer : String) -> Bool {
  if pointer == "" {
    return true
  }
  if !pointer.has_prefix("/") {
    return false
  }
  for segment in pointer.split("/") {
    let mut remaining = segment.to_owned()
    while remaining.find("~") is Some(index) {
      if index + 1 >= remaining.length() {
        return false
      }
      let escaped = remaining[index + 1:index + 2].to_owned()
      if escaped != "0" && escaped != "1" {
        return false
      }
      remaining = remaining[index + 2:].to_owned()
    }
  }
  true
}

///|
fn replace_all(
  input : String,
  pattern : String,
  replacement : String,
) -> String {
  let mut remaining = input
  let mut out = ""
  while remaining.find(pattern) is Some(index) {
    out = out + remaining[:index].to_owned() + replacement
    remaining = remaining[index + pattern.length():].to_owned()
  }
  out + remaining
}

///|
fn json_string_content(value : String) -> String {
  let quoted = Json::string(value).stringify()
  quoted[1:quoted.length() - 1].to_owned()
}

///|
fn render_body_tokens(
  template : String,
  actor_name : String,
  actor_id : String,
  target_id : String,
) -> String {
  let out = replace_all(
    template,
    "{{actor_name}}",
    json_string_content(actor_name),
  )
  let out = replace_all(out, "{{actor_id}}", json_string_content(actor_id))
  replace_all(out, "{{object_id}}", json_string_content(target_id))
}

///|
fn render_write_body(
  config : AppConfig,
  actor : Identity,
  target : Identity,
) -> String raise CliError {
  let template = match config.request_body {
    Some(value) => value
    None => raise CliError("写请求缺少 request.body")
  }
  let body = render_body_tokens(
    template,
    actor.name,
    actor.object_id,
    target.object_id,
  )
  if body.contains("{{") {
    raise CliError("request.body 包含不支持的模板标记")
  }
  ignore(
    @json.parse(body) catch {
      _ => raise CliError("request.body 模板展开后不是有效 JSON")
    },
  )
  body
}

///|
fn render_cleanup_body(
  cleanup : CleanupConfig,
  actor : Identity,
  target : Identity,
  baseline : Array[FieldSnapshot],
) -> String raise CliError {
  let mut body = cleanup.body_template
  for snapshot in baseline {
    body = replace_all(
      body,
      "{{baseline:" + snapshot.pointer + "}}",
      snapshot.value.stringify(),
    )
  }
  body = render_body_tokens(body, actor.name, actor.object_id, target.object_id)
  if body.contains("{{") {
    raise CliError("cleanup.body 包含不支持的模板标记")
  }
  ignore(
    @json.parse(body) catch {
      _ => raise CliError("cleanup.body 模板展开后不是有效 JSON")
    },
  )
  body
}

///|
fn resolve_env(template : String) -> String raise CliError {
  let prefix = "${ENV:"
  let mut remaining = template
  let mut out = ""
  while remaining.find(prefix) is Some(start) {
    out = out + remaining[:start].to_owned()
    let after_prefix = remaining[start + prefix.length():]
    guard after_prefix.find("}") is Some(end) else {
      raise CliError("环境变量模板缺少右花括号")
    }
    let name = after_prefix[:end].to_owned()
    if name == "" {
      raise CliError("环境变量名不能为空")
    }
    let value = match @env.get_env_var(name) {
      Some(value) if value != "" => value
      _ => raise CliError("环境变量未设置: " + name)
    }
    out = out + value
    remaining = after_prefix[end + 1:].to_owned()
  }
  out + remaining
}

///|
fn resolved_headers(
  config : AppConfig,
  identity : Identity,
) -> @http.Headers raise CliError {
  let headers : @http.Headers = Map([])
  for (name, template) in config.common_headers {
    headers[@http.CaseInsensitiveString(name)] = resolve_env(template)
  }
  for (name, template) in identity.headers {
    headers[@http.CaseInsensitiveString(name)] = resolve_env(template)
  }
  if config.request_method != "GET" &&
    !headers.contains(@http.CaseInsensitiveString("Content-Type")) {
    headers[@http.CaseInsensitiveString("Content-Type")] = "application/json"
  }
  headers
}

///|
fn display_headers(
  config : AppConfig,
  identity : Identity,
) -> Map[String, String] {
  let headers : Map[String, String] = Map([])
  for (name, template) in config.common_headers {
    headers[name] = if template.contains("${ENV:") {
      template
    } else {
      "<REDACTED>"
    }
  }
  for (name, template) in identity.headers {
    headers[name] = if template.contains("${ENV:") {
      template
    } else {
      "<REDACTED>"
    }
  }
  if config.request_method != "GET" && !headers.contains("Content-Type") {
    headers["Content-Type"] = "application/json"
  }
  headers
}

///|
fn url_component_encode(value : String) -> String {
  let bytes = @utf8.encode(value)
  let mut out = ""
  let hex = @utf8.encode("0123456789ABCDEF")
  for byte in bytes {
    let value = byte.to_int()
    let unreserved = (value >= 65 && value <= 90) ||
      (value >= 97 && value <= 122) ||
      (value >= 48 && value <= 57) ||
      value == 45 ||
      value == 46 ||
      value == 95 ||
      value == 126
    if unreserved {
      out = out + byte.to_char().to_string()
    } else {
      let high = value / 16
      let low = value % 16
      out = out +
        "%" +
        hex[high].to_char().to_string() +
        hex[low].to_char().to_string()
    }
  }
  out
}

///|
fn build_url(config : AppConfig, object_id : String) -> String {
  let encoded_id = url_component_encode(object_id)
  config.base_url +
  replace_all(config.path_template, "{{object_id}}", encoded_id)
}

///|
fn extract_markers(
  config : AppConfig,
  identity : Identity,
  body : String,
) -> Array[Marker] raise CliError {
  let markers : Array[Marker] = []
  let json = if config.leak_detection == "json_pointer" ||
    identity.sensitive_pointers.length() > 0 {
    Some(
      @json.parse(body) catch {
        _ =>
          raise CliError(
            "自有对象基线响应不是有效 JSON: " + identity.name,
          )
      },
    )
  } else {
    None
  }
  if config.leak_detection == "json_pointer" {
    let root = match json {
      Some(value) => value
      None => raise CliError("结构化泄露检测需要 JSON 基线响应")
    }
    match json_pointer(root, config.object_id_pointer) {
      None =>
        raise CliError(
          "基线响应缺少对象 ID JSON 字段 " +
          config.object_id_pointer +
          " (身份 " +
          identity.name +
          ")",
        )
      Some(value) =>
        match json_marker(value) {
          Some(marker) if marker == identity.object_id =>
            markers.push({
              source: "object_id",
              value: marker,
              pointer: Some(config.object_id_pointer),
              json_value: Some(value),
            })
          _ =>
            raise CliError(
              "基线对象 ID 与配置不匹配: " + identity.name,
            )
        }
    }
  } else {
    markers.push({
      source: "object_id",
      value: identity.object_id,
      pointer: None,
      json_value: None,
    })
  }
  for pointer in identity.sensitive_pointers {
    let root = match json {
      Some(value) => value
      None =>
        raise CliError(
          "自有对象基线响应不是有效 JSON: " + identity.name,
        )
    }
    match json_pointer(root, pointer) {
      None =>
        raise CliError(
          "基线响应缺少敏感 JSON 字段 " +
          pointer +
          " (身份 " +
          identity.name +
          ")",
        )
      Some(value) =>
        match json_marker(value) {
          Some(marker) =>
            markers.push({
              source: pointer,
              value: marker,
              pointer: Some(pointer),
              json_value: Some(value),
            })
          None =>
            raise CliError(
              "基线敏感字段没有可检查的值: " + pointer,
            )
        }
    }
  }
  markers
}

///|
fn extract_state(
  body : String,
  pointers : Array[String],
) -> Array[FieldSnapshot] raise CliError {
  let json = @json.parse(body) catch {
    _ => raise CliError("对象状态响应不是有效 JSON")
  }
  let snapshots : Array[FieldSnapshot] = []
  for pointer in pointers {
    match json_pointer(json, pointer) {
      Some(value) => snapshots.push({ pointer, value, })
      None =>
        raise CliError("对象状态响应缺少受保护字段: " + pointer)
    }
  }
  snapshots
}

///|
fn changed_state_fields(
  body : String,
  baseline : Array[FieldSnapshot],
) -> Array[String] raise CliError {
  let pointers : Array[String] = []
  for snapshot in baseline {
    pointers.push(snapshot.pointer)
  }
  let current = extract_state(body, pointers)
  let changed : Array[String] = []
  for i = 0; i < baseline.length(); i = i + 1 {
    if !Json::equal(baseline[i].value, current[i].value) {
      changed.push(baseline[i].pointer)
    }
  }
  changed
}
