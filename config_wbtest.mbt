///|
fn test_identity(name : String, object_id : String) -> Json {
  Json::object({
    "name": Json::string(name),
    "object_id": Json::string(object_id),
  })
}

///|
fn test_config(names : Array[String], object_ids : Array[String]) -> Json {
  let identities : Array[Json] = []
  for i = 0; i < names.length(); i = i + 1 {
    identities.push(test_identity(names[i], object_ids[i]))
  }
  Json::object({
    "base_url": Json::string("http://127.0.0.1:8095"),
    "request": Json::object({ "path": Json::string("/objects/{{object_id}}") }),
    "identities": Json::array(identities),
    "denied_statuses": Json::array([Json::Json(403), Json::Json(404)]),
  })
}

///|
fn config_is_rejected(config : Json) -> Bool {
  try {
    let _ = parse_config(config)
    false
  } catch {
    _ => true
  }
}

///|
test "config accepts three identities" {
  let config = parse_config(
    test_config(["A", "B", "C"], ["id-a", "id-b", "id-c"]),
  )
  assert_eq(config.identities.length(), 3)
}

///|
test "config allows at most ten identities" {
  let names : Array[String] = []
  let object_ids : Array[String] = []
  for i in 0..<10 {
    names.push("user-" + i.to_string())
    object_ids.push("object-" + i.to_string())
  }
  let config = parse_config(test_config(names, object_ids))
  assert_eq(config.identities.length(), 10)
}

///|
test "config rejects fewer than two identities" {
  assert_true(config_is_rejected(test_config(["A"], ["id-a"])))
}

///|
test "config rejects more than ten identities" {
  let names : Array[String] = []
  let object_ids : Array[String] = []
  for i in 0..<11 {
    names.push("user-" + i.to_string())
    object_ids.push("object-" + i.to_string())
  }
  assert_true(config_is_rejected(test_config(names, object_ids)))
}

///|
test "config rejects duplicate names outside the first pair" {
  assert_true(
    config_is_rejected(
      test_config(["A", "B", "C", "C"], ["id-a", "id-b", "id-c", "id-d"]),
    ),
  )
}

///|
test "config rejects duplicate object IDs outside the first pair" {
  assert_true(
    config_is_rejected(
      test_config(["A", "B", "C", "D"], ["id-a", "id-b", "id-c", "id-c"]),
    ),
  )
}
