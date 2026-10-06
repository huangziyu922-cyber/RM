use rm_server_sync::Service;
use serde_json::{Value, json};
use std::sync::Arc;

const ACCOUNT: &str = r#"{"username":"alice","password":"password1"}"#;

fn account() -> Value {
    serde_json::from_str(ACCOUNT).unwrap()
}

/// Register `name`, log in, and return the `Authorization` header value.
fn sign_in(service: &Service, name: &str) -> String {
    let account = json!({"username": name, "password": "password1"});
    assert_eq!(service.handle("POST", "/users", &account, "").0, 201);
    let login = service.handle("POST", "/sessions", &account, "").1;
    format!("Bearer {}", login["data"]["token"].as_str().unwrap())
}

/// Run one closure per thread and collect what each returned.
fn in_parallel<T, F>(count: usize, work: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn() -> T + Send + Sync + 'static,
{
    let work = Arc::new(work);
    let workers: Vec<_> = (0..count)
        .map(|_| {
            let work = Arc::clone(&work);
            std::thread::spawn(move || work())
        })
        .collect();
    workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect()
}

#[test]
fn input_validation_and_baseline() {
    let service = Service::default();
    assert_eq!(
        service.handle("GET", "/ping", &Value::Null, ""),
        (200, json!({"data":"pong"}))
    );
    for body in [
        Value::Null,
        json!([]),
        json!({"username":true,"password":"password1"}),
        json!({"username":"a/b","password":"password1"}),
    ] {
        assert_eq!(service.handle("POST", "/users", &body, "").0, 400);
    }
    assert_eq!(service.handle("GET", "/texts", &Value::Null, "").0, 401);
    assert_eq!(service.handle("GET", "/missing", &Value::Null, "").0, 404);
}

#[test]
fn concurrent_registration_has_one_winner() {
    let service = std::sync::Arc::new(Service::default());
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let service = service.clone();
            std::thread::spawn(move || {
                service
                    .handle(
                        "POST",
                        "/users",
                        &json!({"username":"alice","password":"password1"}),
                        "",
                    )
                    .0
            })
        })
        .collect();
    let statuses: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(statuses.iter().filter(|&&s| s == 201).count(), 1);
    assert_eq!(statuses.iter().filter(|&&s| s == 409).count(), 3);
}

#[test]
fn concurrent_writes_to_one_name_end_in_one_of_the_written_values() {
    let service = Arc::new(Service::default());
    let auth = sign_in(&service, "alice");

    let written = ["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"];
    // Each thread overwrites the same name. No write may be lost in a way that
    // leaves a torn or empty value: the stored text must be exactly one of the
    // values that were written.
    let workers: Vec<_> = written
        .iter()
        .map(|text| {
            let (service, auth, text) = (Arc::clone(&service), auth.clone(), text.to_string());
            std::thread::spawn(move || {
                service
                    .handle("PUT", "/texts/note", &json!({ "text": text }), &auth)
                    .0
            })
        })
        .collect();
    assert!(
        workers
            .into_iter()
            .all(|worker| worker.join().unwrap() == 200)
    );

    let stored = service.handle("GET", "/texts/note", &Value::Null, &auth).1["data"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        written.contains(&stored.as_str()),
        "stored {stored:?} is not one of the written values"
    );
    assert_eq!(
        service.handle("GET", "/texts", &Value::Null, &auth),
        (200, json!({"data": ["note"]}))
    );
}

#[test]
fn concurrent_writes_to_different_names_all_survive() {
    let service = Arc::new(Service::default());
    let auth = sign_in(&service, "alice");

    let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
    let workers: Vec<_> = names
        .iter()
        .map(|name| {
            let (service, auth, name) = (Arc::clone(&service), auth.clone(), name.to_string());
            std::thread::spawn(move || {
                service
                    .handle(
                        "PUT",
                        &format!("/texts/{name}"),
                        &json!({ "text": name }),
                        &auth,
                    )
                    .0
            })
        })
        .collect();
    assert!(workers.into_iter().all(|w| w.join().unwrap() == 200));

    // Nothing was clobbered: every name is listed, and each reads back its own text.
    assert_eq!(
        service.handle("GET", "/texts", &Value::Null, &auth),
        (200, json!({"data": names}))
    );
    for name in names {
        assert_eq!(
            service.handle("GET", &format!("/texts/{name}"), &Value::Null, &auth),
            (200, json!({"data": name})),
            "{name} did not read back"
        );
    }
}

#[test]
fn concurrent_reads_and_writes_leave_the_store_consistent() {
    let service = Arc::new(Service::default());
    let auth = sign_in(&service, "alice");
    assert_eq!(
        service
            .handle("PUT", "/texts/note", &json!({"text": "seed"}), &auth)
            .0,
        200
    );

    // Writers keep replacing the text; readers keep listing and reading. A reader
    // must never observe a broken state: the listing always contains the name, and
    // reading it always yields one of the values that were written.
    let accepted = ["seed", "w0", "w1", "w2", "w3"];
    let writers: Vec<_> = accepted
        .iter()
        .map(|text| {
            let (service, auth, text) = (Arc::clone(&service), auth.clone(), text.to_string());
            std::thread::spawn(move || {
                for _ in 0..20 {
                    assert_eq!(
                        service
                            .handle("PUT", "/texts/note", &json!({ "text": text }), &auth)
                            .0,
                        200
                    );
                }
            })
        })
        .collect();
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let (service, auth) = (Arc::clone(&service), auth.clone());
            std::thread::spawn(move || {
                for _ in 0..20 {
                    assert_eq!(
                        service.handle("GET", "/texts", &Value::Null, &auth),
                        (200, json!({"data": ["note"]}))
                    );
                    let value = service.handle("GET", "/texts/note", &Value::Null, &auth).1["data"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    assert!(
                        accepted.contains(&value.as_str()),
                        "read a value that was never written: {value:?}"
                    );
                }
            })
        })
        .collect();
    for worker in writers.into_iter().chain(readers) {
        worker.join().unwrap();
    }
}

#[test]
fn concurrent_logins_leave_exactly_one_valid_session() {
    let service = Arc::new(Service::default());
    let auth = sign_in(&service, "alice");
    let first = auth.clone();

    // Eight logins at once. Each must succeed, and the account must end up with
    // exactly one live token: the last one written.
    let logins = in_parallel(8, {
        let service = Arc::clone(&service);
        move || {
            let response = service.handle("POST", "/sessions", &account(), "").1;
            response["data"]["token"].as_str().unwrap().to_owned()
        }
    });
    assert_eq!(logins.len(), 8);

    let valid = logins
        .iter()
        .filter(|token| {
            service
                .handle("GET", "/texts", &Value::Null, &format!("Bearer {token}"))
                .0
                == 200
        })
        .count();
    assert_eq!(valid, 1, "exactly one of the issued tokens may still work");

    // The very first token was replaced by the burst, so it is dead as well.
    assert_eq!(service.handle("GET", "/texts", &Value::Null, &first).0, 401);
}

#[test]
fn concurrent_logout_has_one_winner() {
    let service = Arc::new(Service::default());
    let auth = sign_in(&service, "alice");

    let statuses = in_parallel(8, {
        let service = Arc::clone(&service);
        let auth = auth.clone();
        move || {
            service
                .handle("DELETE", "/sessions/current", &Value::Null, &auth)
                .0
        }
    });
    assert_eq!(statuses.iter().filter(|&&s| s == 200).count(), 1);
    assert_eq!(statuses.iter().filter(|&&s| s == 401).count(), 7);
    assert_eq!(service.handle("GET", "/texts", &Value::Null, &auth).0, 401);
}

#[test]
fn concurrent_account_deletion_has_one_winner() {
    let service = Arc::new(Service::default());
    let auth = sign_in(&service, "alice");

    let statuses = in_parallel(8, {
        let service = Arc::clone(&service);
        let auth = auth.clone();
        move || service.handle("DELETE", "/users/me", &Value::Null, &auth).0
    });
    assert_eq!(statuses.iter().filter(|&&s| s == 200).count(), 1);
    assert_eq!(statuses.iter().filter(|&&s| s == 401).count(), 7);

    // The account is really gone rather than half-removed, so the name is free.
    assert_eq!(service.handle("GET", "/texts", &Value::Null, &auth).0, 401);
    assert_eq!(service.handle("POST", "/users", &account(), "").0, 201);
}

#[test]
fn a_logout_racing_a_write_never_leaves_a_half_written_state() {
    // Both orders are legal, but the outcome must be one of them and never a
    // mixture: either the write happened (then it is readable after a new login)
    // or it was refused (then the text is absent). Repeating the race covers both.
    for _ in 0..25 {
        let service = Arc::new(Service::default());
        let auth = sign_in(&service, "alice");

        let write = {
            let (service, auth) = (Arc::clone(&service), auth.clone());
            std::thread::spawn(move || {
                service
                    .handle("PUT", "/texts/note", &json!({"text": "raced"}), &auth)
                    .0
            })
        };
        let logout = {
            let (service, auth) = (Arc::clone(&service), auth.clone());
            std::thread::spawn(move || {
                service
                    .handle("DELETE", "/sessions/current", &Value::Null, &auth)
                    .0
            })
        };
        let write_status = write.join().unwrap();
        let logout_status = logout.join().unwrap();

        assert_eq!(logout_status, 200, "logout must succeed exactly once");
        assert!(
            write_status == 200 || write_status == 401,
            "a racing write reported {write_status}"
        );

        // Observe the committed state through a fresh session.
        let fresh = {
            let login = service.handle("POST", "/sessions", &account(), "").1;
            format!("Bearer {}", login["data"]["token"].as_str().unwrap())
        };
        let observed = service.handle("GET", "/texts/note", &Value::Null, &fresh);
        if write_status == 200 {
            assert_eq!(
                observed,
                (200, json!({"data": "raced"})),
                "a write that reported success must be readable"
            );
        } else {
            assert_eq!(observed.0, 404, "a refused write must not have stored");
        }
    }
}

#[test]
fn a_rejected_request_does_not_disturb_the_state() {
    let service = Service::default();
    let auth = sign_in(&service, "alice");
    assert_eq!(
        service
            .handle("PUT", "/texts/note", &json!({"text": "good"}), &auth)
            .0,
        200
    );

    // A batch of failures of every kind: bad name, bad body, unknown path, wrong
    // method, missing text, and messages a client should never send.
    let rejected: &[(&str, &str)] = &[
        ("PUT", "/texts/bad.name"),
        ("PUT", "/texts/"),
        ("GET", "/texts/bad.name"),
        ("DELETE", "/texts/bad.name"),
        ("GET", "/missing"),
        ("PATCH", "/texts/note"),
        ("PATCH", "/ping"),
    ];
    for (method, path) in rejected {
        let status = service.handle(method, path, &json!({"text": "x"}), &auth).0;
        assert!(status >= 400, "{method} {path} unexpectedly gave {status}");
    }
    for body in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"text": 42}),
        json!({"text": "x", "extra": 1}),
        json!({"text": "a".repeat(65_537)}),
    ] {
        assert!(service.handle("PUT", "/texts/other", &body, &auth).0 >= 400);
    }

    // Nothing was disturbed: the original text is intact, the rejected names were
    // never created, and a valid request still works.
    assert_eq!(
        service.handle("GET", "/texts/note", &Value::Null, &auth),
        (200, json!({"data": "good"}))
    );
    assert_eq!(
        service.handle("GET", "/texts", &Value::Null, &auth),
        (200, json!({"data": ["note"]}))
    );
    assert_eq!(
        service
            .handle("PUT", "/texts/fresh", &json!({"text": "ok"}), &auth)
            .0,
        200
    );
    assert_eq!(
        service.handle("GET", "/texts", &Value::Null, &auth),
        (200, json!({"data": ["fresh", "note"]}))
    );
    assert_eq!(
        service.handle("GET", "/ping", &Value::Null, ""),
        (200, json!({"data": "pong"}))
    );
}
