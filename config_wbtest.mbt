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

///|
test "config rejects multiple object ID placeholders" {
  let root = test_config(["A", "B"], ["id-a", "id-b"])
  match root {
    Json::Object(fields) => {
      fields["request"] = Json::object({
        "path": Json::string("/objects/{{object_id}}?copy={{object_id}}"),
      })
      assert_true(config_is_rejected(Json::object(fields)))
    }
    _ => fail("test config must be an object")
  }
}

///|
test "config rejects control characters in the request target" {
  let root = test_config(["A", "B"], ["id-a", "id-b"])
  match root {
    Json::Object(fields) => {
      fields["request"] = Json::object({
        "path": Json::string("/objects/{{object_id}}\r\nX-Injected: yes"),
      })
      assert_true(config_is_rejected(Json::object(fields)))
    }
    _ => fail("test config must be an object")
  }
}

///|
test "config rejects malformed JSON Pointer escapes" {
  assert_true(is_json_pointer("/profile/name"))
  assert_true(is_json_pointer("/profile/a~1b/~0key"))
  assert_false(is_json_pointer("/profile/bad~2escape"))
}

///|
test "object IDs are encoded as one path or query component" {
  let path_config = parse_config(test_config(["A", "B"], ["id-a", "id-b"]))
  assert_eq(
    build_url(path_config, "a/b ?#%&"),
    "http://127.0.0.1:8095/objects/a%2Fb%20%3F%23%25%26",
  )
  assert_eq(
    build_url(path_config, "用户"),
    "http://127.0.0.1:8095/objects/%E7%94%A8%E6%88%B7",
  )

  let query_root = test_config(["A", "B"], ["id-a", "id-b"])
  match query_root {
    Json::Object(fields) => {
      fields["request"] = Json::object({
        "path": Json::string("/objects?object={{object_id}}"),
      })
      let query_config = parse_config(Json::object(fields))
      assert_eq(
        build_url(query_config, "a&role=admin"),
        "http://127.0.0.1:8095/objects?object=a%26role%3Dadmin",
      )
    }
    _ => fail("test config must be an object")
  }
}
