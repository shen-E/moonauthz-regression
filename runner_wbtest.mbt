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

///|
test "write body templates JSON-escape identity and object values" {
  let config = parse_config(
    test_write_config(
      "PATCH", "{\"private_note\":\"{{actor_name}} -> {{object_id}} / {{actor_id}}\"}",
    ),
  )
  let actor = config.identities[0]
  let target = config.identities[1]
  let body = render_body_tokens(
    "{\"private_note\":\"{{actor_name}} -> {{object_id}} / {{actor_id}}\"}", "A\"B",
    "actor\\id", "target\nid",
  )
  let parsed = @json.parse(body)
  assert_true(
    json_pointer(parsed, "/private_note")
    is Some(Json::String("A\"B -> target\nid / actor\\id")),
  )
  assert_eq(render_write_body(config, actor, target).length() > 0, true)
}

///|
test "cleanup body restores captured JSON values and state comparisons are exact" {
  let config = parse_config(
    test_write_config("PATCH", "{\"private_note\":\"probe\"}"),
  )
  let cleanup = match config.cleanup {
    Some(value) => value
    None => fail("write config should provide cleanup")
  }
  let target = config.identities[1]
  let baseline : Array[FieldSnapshot] = [
    { pointer: "/private_note", value: Json::string("original \"note\""), },
  ]
  let cleanup_body = render_cleanup_body(cleanup, target, target, baseline)
  let parsed = @json.parse(cleanup_body)
  assert_true(
    json_pointer(parsed, "/private_note")
    is Some(Json::String("original \"note\"")),
  )
  assert_eq(
    changed_state_fields(
      "{\"private_note\":\"original \\\"note\\\"\"}", baseline,
    ).length(),
    0,
  )
  assert_eq(changed_state_fields("{\"private_note\":\"tampered\"}", baseline), [
    "/private_note",
  ])
}
