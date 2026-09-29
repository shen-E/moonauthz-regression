///|
fn marker_test_config() -> AppConfig raise CliError {
  parse_config(test_config(["A", "B"], ["1", "2"]))
}

///|
test "JSON pointer mode avoids short and common substring false positives" {
  let markers : Array[Marker] = [
    {
      source: "object_id",
      value: "1",
      pointer: Some("/id"),
      json_value: Some(Json::string("1")),
    },
    {
      source: "/email",
      value: "Ann",
      pointer: Some("/email"),
      json_value: Some(Json::string("Ann")),
    },
  ]
  let response = "{\"id\":\"10\",\"email\":\"Annette@example.test\"}"
  assert_eq(marker_sources_in(response, markers, "json_pointer").length(), 0)
  assert_eq(marker_sources_in(response, markers, "substring").length(), 2)
}

///|
test "JSON pointer mode detects exact target values at configured fields" {
  let markers : Array[Marker] = [
    {
      source: "object_id",
      value: "1",
      pointer: Some("/data/id"),
      json_value: Some(Json::string("1")),
    },
    {
      source: "/data/email",
      value: "a@example.test",
      pointer: Some("/data/email"),
      json_value: Some(Json::string("a@example.test")),
    },
  ]
  let response = "{\"data\":{\"id\":\"1\",\"email\":\"a@example.test\"}}"
  assert_eq(
    join_strings(marker_sources_in(response, markers, "json_pointer"), ","),
    "object_id,/data/email",
  )
}

///|
test "JSON pointer baseline must match the configured object ID" {
  let config = marker_test_config()
  let identity = config.identities[0]
  let matched = try {
    ignore(extract_markers(config, identity, "{\"id\":\"wrong\"}"))
    false
  } catch {
    CliError(_) => true
  }
  assert_true(matched)
}

///|
test "same origin check rejects a different authority" {
  let config = marker_test_config()
  ensure_same_origin(config, "http://127.0.0.1:8095/objects/1")
  let rejected = try {
    ensure_same_origin(config, "http://example.invalid/objects/1")
    false
  } catch {
    CliError(_) => true
  }
  assert_true(rejected)
}
