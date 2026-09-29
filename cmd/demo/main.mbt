///|
async fn write_json(
  conn : @http.ServerConnection,
  status : Int,
  reason : String,
  body : String,
) -> Unit {
  conn.send_response(status, reason)
  conn.write_string(body)
  conn.end_response()
}

///|
fn order_response(object_id : String) -> String? {
  match object_id {
    "order-a-100" =>
      Some(
        "{\"id\":\"order-a-100\",\"owner\":\"A\",\"email\":\"alice-private@example.test\",\"private_note\":\"A-only shipping note\"}",
      )
    "order-b-200" =>
      Some(
        "{\"id\":\"order-b-200\",\"owner\":\"B\",\"email\":\"bob-private@example.test\",\"private_note\":\"B-only refund note\"}",
      )
    _ => None
  }
}

///|
fn order_owner(object_id : String) -> String? {
  match object_id {
    "order-a-100" => Some("A")
    "order-b-200" => Some("B")
    _ => None
  }
}

///|
fn clean_path(path : String) -> String {
  match path.find("?") {
    Some(index) => path[:index].to_owned()
    None => path
  }
}

///|
fn path_object_id(path : String) -> String? {
  let clean = clean_path(path)
  if clean.has_prefix("/orders/") {
    Some(clean[8:].to_owned())
  } else {
    None
  }
}

///|
async fn serve_request(
  vulnerable : Bool,
  request : @http.Request,
  conn : @http.ServerConnection,
) -> Unit {
  if request.meth != Get {
    return write_json(
      conn, 405, "Method Not Allowed", "{\"error\":\"method_not_allowed\"}",
    )
  }
  let actor = match
    request.headers.get(@http.CaseInsensitiveString("Authorization")) {
    Some("Bearer demo-token-a") => Some("A")
    Some("Bearer demo-token-b") => Some("B")
    _ => None
  }
  match actor {
    None =>
      write_json(conn, 401, "Unauthorized", "{\"error\":\"unauthorized\"}")
    Some(user) =>
      match path_object_id(request.path) {
        None => write_json(conn, 404, "Not Found", "{\"error\":\"not_found\"}")
        Some(object_id) =>
          match order_response(object_id) {
            None =>
              write_json(conn, 404, "Not Found", "{\"error\":\"not_found\"}")
            Some(body) =>
              if vulnerable || order_owner(object_id) == Some(user) {
                write_json(conn, 200, "OK", body)
              } else {
                // Conceal cross-user objects with the same response used for missing IDs.
                write_json(conn, 404, "Not Found", "{\"error\":\"not_found\"}")
              }
          }
      }
  }
}

///|
fn main_arguments() -> Array[String] {
  let raw = @env.args()
  let args : Array[String] = []
  for index = 1; index < raw.length(); index = index + 1 {
    args.push(raw[index])
  }
  args
}

///|
fn demo_mode(args : Array[String]) -> String {
  let mut index = 0
  while index + 1 < args.length() {
    if args[index] == "--mode" {
      return args[index + 1]
    }
    index = index + 1
  }
  "safe"
}

///|
async fn main {
  let mode = demo_mode(main_arguments())
  if mode != "safe" && mode != "vulnerable" {
    println("用法: moon run cmd/demo -- --mode safe|vulnerable")
    @sys.exit(2)
  }
  let vulnerable = mode == "vulnerable"
  println("Demo API 模式: \{mode}")
  println("监听地址: http://127.0.0.1:8095")
  let server = @http.Server(@socket.Addr::parse("127.0.0.1:8095"))
  server.run_forever((request, _body, conn) => {
    serve_request(vulnerable, request, conn)
  })
}
