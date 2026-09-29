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
priv struct DemoOrder {
  owner : String
  email : String
  mut private_note : String
}

///|
fn demo_orders() -> Map[String, DemoOrder] {
  Map::from_array([
    (
      "order-a-100",
      {
        owner: "A",
        email: "alice-private@example.test",
        private_note: "A-only shipping note",
      },
    ),
    (
      "order-b-200",
      {
        owner: "B",
        email: "bob-private@example.test",
        private_note: "B-only refund note",
      },
    ),
    (
      "order-c-300",
      {
        owner: "C",
        email: "carol-private@example.test",
        private_note: "C-only invoice note",
      },
    ),
  ])
}

///|
fn order_response(object_id : String, order : DemoOrder) -> String {
  Json::object({
    "id": Json::string(object_id),
    "owner": Json::string(order.owner),
    "email": Json::string(order.email),
    "private_note": Json::string(order.private_note),
  }).stringify()
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
  orders : Map[String, DemoOrder],
  request : @http.Request,
  body_reader : &@io.Reader,
  conn : @http.ServerConnection,
) -> Unit {
  let body_text = if request.meth == @http.Get {
    ""
  } else {
    body_reader.read_all().text()
  }
  if request.meth != @http.Get &&
    request.meth != @http.Post &&
    request.meth != @http.Put &&
    request.meth != @http.Patch {
    return write_json(
      conn, 405, "Method Not Allowed", "{\"error\":\"method_not_allowed\"}",
    )
  }
  let actor = match
    request.headers.get(@http.CaseInsensitiveString("Authorization")) {
    Some("Bearer demo-token-a") => Some("A")
    Some("Bearer demo-token-b") => Some("B")
    Some("Bearer demo-token-c") => Some("C")
    _ => None
  }
  match actor {
    None =>
      write_json(conn, 401, "Unauthorized", "{\"error\":\"unauthorized\"}")
    Some(user) =>
      match path_object_id(request.path) {
        None => write_json(conn, 404, "Not Found", "{\"error\":\"not_found\"}")
        Some(object_id) =>
          match orders.get(object_id) {
            None =>
              write_json(conn, 404, "Not Found", "{\"error\":\"not_found\"}")
            Some(order) =>
              if request.meth == @http.Get {
                if vulnerable || order.owner == user {
                  write_json(conn, 200, "OK", order_response(object_id, order))
                } else {
                  // Conceal cross-user objects with the same response used for missing IDs.
                  write_json(
                    conn, 404, "Not Found", "{\"error\":\"not_found\"}",
                  )
                }
              } else if !vulnerable && order.owner != user {
                write_json(conn, 404, "Not Found", "{\"error\":\"not_found\"}")
              } else {
                let payload = @json.parse(body_text) catch {
                  _ =>
                    return write_json(
                      conn, 400, "Bad Request", "{\"error\":\"invalid_json\"}",
                    )
                }
                let private_note = match payload {
                  Json::Object(fields) =>
                    match fields.get("private_note") {
                      Some(Json::String(value)) => value
                      _ =>
                        return write_json(
                          conn, 400, "Bad Request", "{\"error\":\"private_note_required\"}",
                        )
                    }
                  _ =>
                    return write_json(
                      conn, 400, "Bad Request", "{\"error\":\"json_object_required\"}",
                    )
                }
                let updated = order
                updated.private_note = private_note
                orders[object_id] = updated
                if order.owner == user {
                  conn.send_response(204, "No Content")
                  conn.end_response()
                } else {
                  let updated_order = orders[object_id]
                  write_json(
                    conn,
                    200,
                    "OK",
                    order_response(object_id, updated_order),
                  )
                }
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
  let orders = demo_orders()
  println("Demo API 模式: \{mode}")
  println("监听地址: http://127.0.0.1:8095")
  let server = @http.Server(@socket.Addr::parse("127.0.0.1:8095"))
  server.run_forever((request, body, conn) => {
    serve_request(vulnerable, orders, request, body, conn)
  })
}
