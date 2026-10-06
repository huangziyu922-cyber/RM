use rm_server_sync::{
    Service,
    http::{create_app, with_service},
};
use rocket::http::{ContentType, Header, Status};
use rocket::local::blocking::Client;
use serde_json::{Value, json};

#[test]
fn app_uses_supplied_service() {
    let service = Service::default();
    let account = json!({"username": "alice", "password": "password1"});
    assert_eq!(service.handle("POST", "/users", &account, "").0, 201);
    let configured = Client::tracked(with_service(service)).unwrap();
    let fresh = Client::tracked(create_app()).unwrap();
    for (client, expected) in [(&configured, Status::Ok), (&fresh, Status::Unauthorized)] {
        assert_eq!(
            client
                .post("/sessions")
                .header(ContentType::JSON)
                .body(account.to_string())
                .dispatch()
                .status(),
            expected
        );
    }
}

#[test]
fn http_account_lifecycle() {
    let client = Client::tracked(create_app()).unwrap();
    let ping = client.get("/ping").dispatch();
    assert_eq!(ping.status(), Status::Ok);
    assert_eq!(ping.into_json::<Value>().unwrap(), json!({"data": "pong"}));
    let account = json!({"username": "alice", "password": "password1"}).to_string();
    assert_eq!(
        client
            .post("/users")
            .header(ContentType::JSON)
            .body(&account)
            .dispatch()
            .status(),
        Status::Created
    );
    let login = client
        .post("/sessions")
        .header(ContentType::JSON)
        .body(&account)
        .dispatch()
        .into_json::<Value>()
        .unwrap();
    let authorization = format!("Bearer {}", login["data"]["token"].as_str().unwrap());
    let texts = client
        .get("/texts")
        .header(Header::new("Authorization", authorization.clone()))
        .dispatch();
    assert_eq!(texts.status(), Status::Ok);
    assert_eq!(texts.into_json::<Value>().unwrap(), json!({"data": []}));
    assert_eq!(
        client.get("/texts").dispatch().status(),
        Status::Unauthorized
    );
    assert_eq!(
        client
            .delete("/sessions/current")
            .header(Header::new("Authorization", authorization.clone()))
            .dispatch()
            .status(),
        Status::Ok
    );
    assert_eq!(
        client
            .get("/texts")
            .header(Header::new("Authorization", authorization))
            .dispatch()
            .status(),
        Status::Unauthorized
    );
}

#[test]
fn http_input_and_routing() {
    let client = Client::tracked(create_app()).unwrap();
    for body in [b"not JSON".to_vec(), vec![0xff], b"NaN".to_vec()] {
        assert_eq!(
            client
                .post("/users")
                .header(ContentType::JSON)
                .body(body)
                .dispatch()
                .status(),
            Status::BadRequest
        );
    }
    let exact = format!("{{}}{}", " ".repeat(524_288 - 2));
    assert_eq!(
        client
            .post("/users")
            .header(ContentType::JSON)
            .body(&exact)
            .dispatch()
            .status(),
        Status::BadRequest
    );
    assert_eq!(
        client
            .post("/users")
            .header(ContentType::JSON)
            .body(format!("{exact} "))
            .dispatch()
            .status(),
        Status::PayloadTooLarge
    );
    assert_eq!(
        client
            .post("/users")
            .header(ContentType::JSON)
            .body(r#"{"username":true,"password":"password1"}"#)
            .dispatch()
            .status(),
        Status::BadRequest
    );
    // Unknown path: 404. Known path with the wrong method: 405.
    assert_eq!(client.get("/missing").dispatch().status(), Status::NotFound);
    assert_eq!(
        client.get("/echo").dispatch().status(),
        Status::MethodNotAllowed
    );
    assert_eq!(
        client.patch("/ping").dispatch().status(),
        Status::MethodNotAllowed
    );
}

#[test]
fn unimplemented_routes_are_absent() {
    use rocket::http::Method;
    let client = Client::tracked(create_app()).unwrap();
    // `/texts/<name>` is a real route now, so it answers 400/401/405 instead of
    // 404. Only `/users/me` (a later task) is still unimplemented.
    assert_eq!(
        client.req(Method::Delete, "/users/me").dispatch().status(),
        Status::NotFound
    );
    for path in [
        "/ping",
        "/echo",
        "/users",
        "/sessions",
        "/sessions/current",
        "/texts",
        "/texts/note",
    ] {
        assert_eq!(
            client.patch(path).dispatch().status(),
            Status::MethodNotAllowed
        );
    }
}

#[test]
fn http_echo_returns_the_text_unchanged() {
    let client = Client::tracked(create_app()).unwrap();
    // No Authorization header: /echo is a public route.
    for text in ["", "hello", "hello\nworld", "你好\n世界", "trailing\n"] {
        let response = client
            .post("/echo")
            .header(ContentType::JSON)
            .body(json!({"text": text}).to_string())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json::<Value>().unwrap(),
            json!({"data": text})
        );
    }
}

#[test]
fn http_echo_rejects_bad_bodies() {
    let client = Client::tracked(create_app()).unwrap();
    for body in [
        json!([]),
        json!({}),
        json!({"text": 42}),
        json!({"text": "hi", "extra": 1}),
    ] {
        assert_eq!(
            client
                .post("/echo")
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .status(),
            Status::BadRequest,
            "body {body} should be rejected"
        );
    }
}

#[test]
fn http_echo_text_limit_boundary() {
    let client = Client::tracked(create_app()).unwrap();
    let at_limit = json!({"text": "a".repeat(65_536)}).to_string();
    assert_eq!(
        client
            .post("/echo")
            .header(ContentType::JSON)
            .body(at_limit)
            .dispatch()
            .status(),
        Status::Ok
    );
    let over_limit = json!({"text": "a".repeat(65_537)}).to_string();
    assert_eq!(
        client
            .post("/echo")
            .header(ContentType::JSON)
            .body(over_limit)
            .dispatch()
            .status(),
        Status::PayloadTooLarge
    );
}

#[test]
fn http_text_round_trip_and_isolation() {
    let client = Client::tracked(create_app()).unwrap();
    let sign_up = |name: &str| -> String {
        let account = json!({"username": name, "password": "password1"}).to_string();
        assert_eq!(
            client
                .post("/users")
                .header(ContentType::JSON)
                .body(&account)
                .dispatch()
                .status(),
            Status::Created
        );
        let login = client
            .post("/sessions")
            .header(ContentType::JSON)
            .body(&account)
            .dispatch()
            .into_json::<Value>()
            .unwrap();
        format!("Bearer {}", login["data"]["token"].as_str().unwrap())
    };
    let alice = sign_up("alice");
    let bob = sign_up("bob");

    // The same name is created separately for each user.
    for (auth, text) in [(&alice, "from-alice"), (&bob, "from-bob")] {
        let response = client
            .put("/texts/note")
            .header(ContentType::JSON)
            .header(Header::new("Authorization", auth.clone()))
            .body(json!({"text": text}).to_string())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json::<Value>().unwrap(),
            json!({"data": null})
        );
    }

    // Each token reads back its own text under the same name.
    for (auth, expected) in [(&alice, "from-alice"), (&bob, "from-bob")] {
        let response = client
            .get("/texts/note")
            .header(Header::new("Authorization", auth.clone()))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json::<Value>().unwrap(),
            json!({"data": expected})
        );
    }

    let auth = Header::new("Authorization", alice.clone());
    assert_eq!(
        client.get("/texts/note").dispatch().status(),
        Status::Unauthorized
    );
    assert_eq!(
        client
            .get("/texts/bad.name")
            .header(auth.clone())
            .dispatch()
            .status(),
        Status::BadRequest
    );
    assert_eq!(
        client
            .get("/texts/missing")
            .header(auth)
            .dispatch()
            .status(),
        Status::NotFound
    );
}
