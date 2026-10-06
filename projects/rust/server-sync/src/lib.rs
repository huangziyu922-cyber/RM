pub mod http;
mod infrastructure;

use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Mutex;
use subtle::ConstantTimeEq;

pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/ping"),
    ("POST", "/echo"),
    ("POST", "/users"),
    ("POST", "/sessions"),
    ("DELETE", "/sessions/current"),
    ("DELETE", "/users/me"),
    ("GET", "/texts"),
];

/// Text routes are shaped `/texts/<name>`: the name is whatever follows the
/// prefix, and it may be empty. Whether that name is *valid* is the business
/// layer's decision, not routing's.
pub fn text_name(path: &str) -> Option<&str> {
    path.strip_prefix("/texts/")
}

pub fn route_error(method: &str, path: &str) -> Option<u16> {
    if text_name(path).is_some() {
        // Declare the path's whole method set once, so the answer stays stable as
        // the business layer implements these one at a time. Methods it does not
        // handle yet fall through to the business layer's own 404.
        return match method {
            "GET" | "PUT" | "DELETE" => None,
            _ => Some(405),
        };
    }
    match ROUTES.iter().find(|(_, route)| *route == path) {
        None => Some(404),
        Some((allowed, _)) if *allowed != method => Some(405),
        Some(_) => None,
    }
}

pub struct User {
    pub salt: [u8; 16],
    pub digest: [u8; 32],
    pub token: Option<String>,
    pub texts: BTreeMap<String, String>,
}

#[derive(Default)]
pub struct Service {
    pub users: Mutex<BTreeMap<String, User>>,
    /// Test-only pause point, invoked while logging in *after* the password has
    /// been verified against a snapshot of the account but *before* the lock is
    /// taken again to record the session. It exists so a test can pin the exact
    /// interleaving the protocol requires (account deleted and re-registered during
    /// a login) instead of hoping to hit it by timing. Never set outside tests.
    #[cfg(test)]
    pub(crate) after_password_check: Option<Box<dyn Fn() + Send + Sync>>,
}

pub fn error(status: u16, message: &str) -> (u16, Value) {
    (status, json!({"message": message}))
}

pub fn valid_name(name: &str, max: usize) -> bool {
    !name.is_empty()
        && name.len() <= max
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn password_hash(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut output = [0; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut output);
    output
}

fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Service {
    pub fn handle(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        authorization: &str,
    ) -> (u16, Value) {
        if let Some(status) = route_error(method, path) {
            return error(
                status,
                if status == 404 {
                    "Not found"
                } else {
                    "Method not allowed"
                },
            );
        }
        if method == "GET" && path == "/ping" {
            return (200, json!({"data": "pong"}));
        }
        if method == "POST" && path == "/echo" {
            let Some(fields) = body.as_object() else {
                return error(400, "Expected a JSON object");
            };
            let Some(text) = fields.get("text").and_then(Value::as_str) else {
                return error(400, "Expected text");
            };
            if fields.len() != 1 {
                return error(400, "Unexpected fields");
            }
            if text.len() > 65_536 {
                return error(413, "Text too long");
            }
            return (200, json!({"data": text}));
        }
        if method == "POST" && matches!(path, "/users" | "/sessions") {
            let Some(name) = body.get("username").and_then(Value::as_str) else {
                return error(400, "Expected username");
            };
            let Some(password) = body.get("password").and_then(Value::as_str) else {
                return error(400, "Expected password");
            };
            if body.as_object().map(|v| v.len()) != Some(2)
                || !valid_name(name, 32)
                || !(8..=128).contains(&password.chars().count())
            {
                return error(400, "Invalid account fields");
            }
            if path == "/users" {
                let mut salt = [0; 16];
                OsRng.fill_bytes(&mut salt);
                let digest = password_hash(password, &salt);
                let mut users = self.users.lock().unwrap();
                if users.contains_key(name) {
                    return error(409, "Username exists");
                }
                users.insert(
                    name.into(),
                    User {
                        salt,
                        digest,
                        token: None,
                        texts: BTreeMap::new(),
                    },
                );
                return (201, json!({"data": {"username": name}}));
            }
            let (salt, expected) = {
                let users = self.users.lock().unwrap();
                let Some(user) = users.get(name) else {
                    return error(401, "Invalid username or password");
                };
                (user.salt, user.digest)
            };
            let digest = password_hash(password, &salt);
            #[cfg(test)]
            if let Some(pause) = &self.after_password_check {
                pause();
            }
            let mut users = self.users.lock().unwrap();
            let Some(user) = users.get_mut(name) else {
                return error(401, "Invalid username or password");
            };
            // `salt != salt` is not redundant with the digest comparison. The password
            // was verified against a snapshot of this account taken before the hash was
            // computed, and the lock was released in between. During that window the
            // account could have been deleted (`DELETE /users/me`) and a *different*
            // account could have registered the same username. The digest of that new
            // account matches the submitted password too — the password is the same —
            // so only the salt, which is regenerated on every `POST /users`, tells the
            // two registrations apart. A login that started against the old account
            // must not hand a session to the new one.
            if user.salt != salt || !bool::from(digest.ct_eq(&expected)) {
                return error(401, "Invalid username or password");
            }
            let token = new_token();
            user.token = Some(token.clone());
            // Later server task: record a deadline and include expires_in.
            return (200, json!({"data": {"token": token}}));
        }
        // `/users/me` is protected too, but it is handled *before* the borrow below:
        // deleting an account must remove it from the map, and the per-user handle
        // taken there is a borrow that would still be alive at that point.
        let protected = matches!(path, "/texts" | "/sessions/current" | "/users/me")
            || text_name(path).is_some();
        if protected {
            let token = authorization.strip_prefix("Bearer ").unwrap_or("");
            let mut users = self.users.lock().unwrap();
            let name = users
                .iter()
                .find(|(_, user)| !token.is_empty() && user.token.as_deref() == Some(token))
                .map(|(name, _)| name.clone());
            let Some(name) = name else {
                return error(401, "Login required");
            };
            // DELETE /users/me: remove the account itself, along with everything
            // that belonged to it. Dropping the whole `User` value takes the texts
            // and the token with it, so there is nothing left for the old identity
            // to reach — "old token stops working" is a consequence of the account
            // being gone, not a separate step that could be forgotten. Registering
            // the same username afterwards creates a brand new `User` with an empty
            // `texts` map, so no old data can reappear.
            if method == "DELETE" && path == "/users/me" {
                users.remove(&name);
                return (200, json!({"data": null}));
            }
            let user = users.get_mut(&name).unwrap();
            // Later server task: check expiry and keep authorization and state mutation atomic.
            if method == "DELETE" && path == "/sessions/current" {
                user.token = None;
                return (200, json!({"data": null}));
            }
            if method == "GET" && path == "/texts" {
                return (200, json!({"data": user.texts.keys().collect::<Vec<_>>()}));
            }
            // PUT /texts/<name>: create or overwrite one text *for this user*.
            // `text_key` is the protocol's `name` path parameter, used here as the
            // key into `user.texts`. The owner comes from the token, never from the
            // request, which is what keeps users isolated.
            if method == "PUT"
                && let Some(text_key) = text_name(path)
            {
                if !valid_name(text_key, 64) {
                    return error(400, "Invalid text name");
                }
                let Some(fields) = body.as_object() else {
                    return error(400, "Expected a JSON object");
                };
                let Some(text) = fields.get("text").and_then(Value::as_str) else {
                    return error(400, "Expected text");
                };
                if fields.len() != 1 {
                    return error(400, "Unexpected fields");
                }
                if text.len() > 65_536 {
                    return error(413, "Text too long");
                }
                user.texts.insert(text_key.to_string(), text.to_string());
                return (200, json!({"data": null}));
            }
            // GET /texts/<name>: read one of *this user's* texts. A text that
            // exists but belongs to another user is reported exactly like one that
            // does not exist, so this response cannot be used to discover other
            // users' text names.
            if method == "GET"
                && let Some(text_key) = text_name(path)
            {
                if !valid_name(text_key, 64) {
                    return error(400, "Invalid text name");
                }
                let Some(text) = user.texts.get(text_key) else {
                    return error(404, "Text not found");
                };
                return (200, json!({"data": text}));
            }
            // DELETE /texts/<name>: drop one of *this user's* texts.
            //
            // `remove` answers both questions at once: `Some(_)` means the text
            // existed and is now gone, `None` means this user never had it. A text
            // belonging to somebody else is therefore a plain 404 here — the same
            // status and the same body as a missing one, so the reply cannot be used
            // to learn which names other users own.
            if method == "DELETE"
                && let Some(text_key) = text_name(path)
            {
                if !valid_name(text_key, 64) {
                    return error(400, "Invalid text name");
                }
                if user.texts.remove(text_key).is_none() {
                    return error(404, "Text not found");
                }
                return (200, json!({"data": null}));
            }
        }
        error(404, "Not found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};

    #[test]
    fn account_lifecycle() {
        let service = Service::default();
        let account = json!({"username":"alice", "password":"password1"});
        assert_eq!(service.handle("POST", "/users", &account, "").0, 201);
        assert_eq!(service.handle("POST", "/users", &account, "").0, 409);
        let login = service.handle("POST", "/sessions", &account, "").1;
        let old = format!("Bearer {}", login["data"]["token"].as_str().unwrap());
        let login = service.handle("POST", "/sessions", &account, "").1;
        let current = format!("Bearer {}", login["data"]["token"].as_str().unwrap());
        assert_ne!(old, current);
        assert_eq!(service.handle("GET", "/texts", &Value::Null, &old).0, 401);
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &current),
            (200, json!({"data":[]}))
        );
        assert_eq!(
            service
                .handle("DELETE", "/sessions/current", &Value::Null, &current)
                .0,
            200
        );
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &current).0,
            401
        );
    }

    #[test]
    fn echo_returns_the_text_unchanged() {
        let service = Service::default();
        for text in ["", "hello", "hello\nworld", "你好\n世界", "trailing\n"] {
            assert_eq!(
                service.handle("POST", "/echo", &json!({ "text": text }), ""),
                (200, json!({ "data": text }))
            );
        }
    }

    #[test]
    fn echo_rejects_bodies_that_are_not_exactly_one_text_field() {
        let service = Service::default();
        for body in [
            Value::Null,
            json!([]),
            json!({}),
            json!({ "text": 42 }),
            json!({ "text": "hi", "extra": 1 }),
        ] {
            assert_eq!(
                service.handle("POST", "/echo", &body, "").0,
                400,
                "{body} should be rejected"
            );
        }
    }

    #[test]
    fn echo_text_limit_is_65536_bytes() {
        let service = Service::default();
        let within_limit = json!({ "text": "a".repeat(65_536) });
        assert_eq!(service.handle("POST", "/echo", &within_limit, "").0, 200);
        let over_limit = json!({ "text": "a".repeat(65_537) });
        assert_eq!(service.handle("POST", "/echo", &over_limit, "").0, 413);
    }

    /// Register `account`, log in, and return the `Authorization` header value.
    fn sign_up(service: &Service, account: &Value) -> String {
        assert_eq!(service.handle("POST", "/users", account, "").0, 201);
        let login = service.handle("POST", "/sessions", account, "").1;
        format!("Bearer {}", login["data"]["token"].as_str().unwrap())
    }

    fn alice() -> Value {
        json!({"username": "alice", "password": "password1"})
    }

    #[test]
    fn a_text_can_be_created_overwritten_and_read_back() {
        let service = Service::default();
        let auth = sign_up(&service, &alice());

        assert_eq!(
            service.handle("PUT", "/texts/note", &json!({"text": "v1"}), &auth),
            (200, json!({"data": null}))
        );
        assert_eq!(
            service.handle("GET", "/texts/note", &Value::Null, &auth),
            (200, json!({"data": "v1"}))
        );

        // The same name overwrites instead of creating a second entry.
        assert_eq!(
            service
                .handle("PUT", "/texts/note", &json!({"text": "v2"}), &auth)
                .0,
            200
        );
        assert_eq!(
            service.handle("GET", "/texts/note", &Value::Null, &auth),
            (200, json!({"data": "v2"}))
        );

        // An empty text is a stored value, not a missing one.
        assert_eq!(
            service
                .handle("PUT", "/texts/empty", &json!({"text": ""}), &auth)
                .0,
            200
        );
        assert_eq!(
            service.handle("GET", "/texts/empty", &Value::Null, &auth),
            (200, json!({"data": ""}))
        );

        // The listing is sorted and holds exactly what was stored.
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &auth),
            (200, json!({"data": ["empty", "note"]}))
        );
    }

    #[test]
    fn text_requests_are_rejected_for_the_right_reasons() {
        let service = Service::default();
        let auth = sign_up(&service, &alice());

        // 401: no token, or a token that identifies nobody.
        assert_eq!(
            service
                .handle("PUT", "/texts/note", &json!({"text": "v"}), "")
                .0,
            401
        );
        assert_eq!(
            service
                .handle("GET", "/texts/note", &Value::Null, "Bearer nope")
                .0,
            401
        );

        // 400: the name itself is not a legal text name.
        for path in ["/texts/", "/texts/bad.name", "/texts/中文"] {
            assert_eq!(
                service.handle("PUT", path, &json!({"text": "v"}), &auth).0,
                400,
                "{path} should be rejected"
            );
            assert_eq!(
                service.handle("GET", path, &Value::Null, &auth).0,
                400,
                "{path} should be rejected"
            );
        }

        // 400: the body is not exactly `{"text": <string>}`.
        for body in [
            Value::Null,
            json!([]),
            json!({}),
            json!({"text": 42}),
            json!({"text": "v", "extra": 1}),
        ] {
            assert_eq!(
                service.handle("PUT", "/texts/note", &body, &auth).0,
                400,
                "{body} should be rejected"
            );
        }

        // 413: the text itself is over the limit.
        assert_eq!(
            service
                .handle(
                    "PUT",
                    "/texts/note",
                    &json!({"text": "a".repeat(65_537)}),
                    &auth
                )
                .0,
            413
        );

        // 404: a legal name this user never stored.
        assert_eq!(
            service
                .handle("GET", "/texts/missing", &Value::Null, &auth)
                .0,
            404
        );
    }

    #[test]
    fn a_text_can_be_deleted_and_the_listing_follows() {
        let service = Service::default();
        let auth = sign_up(&service, &alice());
        for name in ["b", "a", "c"] {
            assert_eq!(
                service
                    .handle(
                        "PUT",
                        &format!("/texts/{name}"),
                        &json!({"text": "v"}),
                        &auth
                    )
                    .0,
                200
            );
        }

        // A text that exists is removed, and that is visible in both views.
        assert_eq!(
            service.handle("DELETE", "/texts/a", &Value::Null, &auth),
            (200, json!({"data": null}))
        );
        assert_eq!(
            service.handle("GET", "/texts/a", &Value::Null, &auth).0,
            404
        );
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &auth),
            (200, json!({"data": ["b", "c"]}))
        );

        // Deleting what is not there is a 404, and repeating it stays a 404
        // instead of reporting the second attempt as a success.
        assert_eq!(
            service.handle("DELETE", "/texts/a", &Value::Null, &auth).0,
            404
        );
        assert_eq!(
            service
                .handle("DELETE", "/texts/missing", &Value::Null, &auth)
                .0,
            404
        );
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &auth),
            (200, json!({"data": ["b", "c"]}))
        );

        // An empty text is a stored value, so deleting it is a real deletion.
        assert_eq!(
            service
                .handle("PUT", "/texts/empty", &json!({"text": ""}), &auth)
                .0,
            200
        );
        assert_eq!(
            service
                .handle("DELETE", "/texts/empty", &Value::Null, &auth)
                .0,
            200
        );
        assert_eq!(
            service.handle("GET", "/texts/empty", &Value::Null, &auth).0,
            404
        );
    }

    #[test]
    fn delete_is_rejected_for_the_right_reasons() {
        let service = Service::default();
        let auth = sign_up(&service, &alice());
        assert_eq!(
            service
                .handle("PUT", "/texts/note", &json!({"text": "v"}), &auth)
                .0,
            200
        );

        // 401: no token, or a token that identifies nobody. Neither may remove
        // anything.
        assert_eq!(
            service.handle("DELETE", "/texts/note", &Value::Null, "").0,
            401
        );
        assert_eq!(
            service
                .handle("DELETE", "/texts/note", &Value::Null, "Bearer nope")
                .0,
            401
        );

        // 400: the name itself is not a legal text name. The check must run before
        // the lookup, so this is 400 rather than 404.
        for path in ["/texts/", "/texts/bad.name", "/texts/中文"] {
            assert_eq!(
                service.handle("DELETE", path, &Value::Null, &auth).0,
                400,
                "{path} should be rejected"
            );
        }

        // The rejected requests above must not have touched the stored text.
        assert_eq!(
            service.handle("GET", "/texts/note", &Value::Null, &auth),
            (200, json!({"data": "v"}))
        );
    }

    #[test]
    fn deleting_one_users_text_leaves_the_others_copy_alone() {
        let service = Service::default();
        let a = sign_up(&service, &alice());
        let b = sign_up(
            &service,
            &json!({"username": "bob", "password": "password1"}),
        );
        for (auth, text) in [(&a, "from-alice"), (&b, "from-bob")] {
            assert_eq!(
                service
                    .handle("PUT", "/texts/note", &json!({"text": text}), auth)
                    .0,
                200
            );
        }

        assert_eq!(
            service.handle("DELETE", "/texts/note", &Value::Null, &a),
            (200, json!({"data": null}))
        );

        // Alice's copy is gone...
        assert_eq!(
            service.handle("GET", "/texts/note", &Value::Null, &a).0,
            404
        );
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &a),
            (200, json!({"data": []}))
        );

        // ...and bob's is untouched, under the very same name.
        assert_eq!(
            service.handle("GET", "/texts/note", &Value::Null, &b),
            (200, json!({"data": "from-bob"}))
        );
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &b),
            (200, json!({"data": ["note"]}))
        );

        // Bob deleting under a name alice owns is a plain 404, and alice's text is
        // still there afterwards.
        assert_eq!(
            service
                .handle("PUT", "/texts/secret", &json!({"text": "alice-only"}), &a)
                .0,
            200
        );
        assert_eq!(
            service
                .handle("DELETE", "/texts/secret", &Value::Null, &b)
                .0,
            404
        );
        assert_eq!(
            service.handle("GET", "/texts/secret", &Value::Null, &a),
            (200, json!({"data": "alice-only"}))
        );
    }

    #[test]
    fn deleting_an_account_takes_its_texts_and_token_with_it() {
        let service = Service::default();
        let auth = sign_up(&service, &alice());
        assert_eq!(
            service
                .handle("PUT", "/texts/note", &json!({"text": "v1"}), &auth)
                .0,
            200
        );
        assert_eq!(
            service.handle("GET", "/texts/note", &Value::Null, &auth),
            (200, json!({"data": "v1"}))
        );

        assert_eq!(
            service.handle("DELETE", "/users/me", &Value::Null, &auth),
            (200, json!({"data": null}))
        );

        // The token was carried by the account, so removing the account removes the
        // session too: every protected route now rejects it.
        for (method, path) in [
            ("GET", "/texts"),
            ("GET", "/texts/note"),
            ("PUT", "/texts/note"),
            ("DELETE", "/texts/note"),
            ("DELETE", "/sessions/current"),
            ("DELETE", "/users/me"),
        ] {
            assert_eq!(
                service
                    .handle(method, path, &json!({"text": "v2"}), &auth)
                    .0,
                401,
                "{method} {path} should reject the deleted account's token"
            );
        }

        // Registering the same name again is allowed, and starts from nothing:
        // no texts, and no token inherited from the old account.
        let fresh = sign_up(&service, &alice());
        assert_ne!(fresh, auth);
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &fresh),
            (200, json!({"data": []}))
        );
        assert_eq!(
            service.handle("GET", "/texts/note", &Value::Null, &fresh).0,
            404
        );
        assert_eq!(service.handle("GET", "/texts", &Value::Null, &auth).0, 401);
    }

    #[test]
    fn a_login_that_started_before_the_account_was_recreated_does_not_apply() {
        let mut service = Service::default();
        let auth = sign_up(&service, &alice());
        assert_eq!(
            service
                .handle("PUT", "/texts/note", &json!({"text": "v1"}), &auth)
                .0,
            200
        );

        // Pin the interleaving the protocol warns about instead of hoping to hit it
        // by timing. The login starts first and parks at the point where it has
        // already verified the password against the old account's record but has not
        // yet recorded a session; only then is the account replaced, with the same
        // username and the same password.
        //
        // The hook parks only on its first call and lets later logins through, so the
        // test can drive one precise interleaving and then let the service work
        // normally. Every piece has to be `Send + Sync` because `Service` is shared
        // across threads, and a `Barrier` plus an `AtomicBool` both are.
        let paused = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let once = Arc::new(AtomicBool::new(true));
        service.after_password_check = Some(Box::new({
            let (paused, resume, once) =
                (Arc::clone(&paused), Arc::clone(&resume), Arc::clone(&once));
            move || {
                if once.swap(false, Ordering::SeqCst) {
                    // Hand control to the test, and do not continue until it has
                    // replaced the account.
                    paused.wait();
                    resume.wait();
                }
            }
        }));

        std::thread::scope(|scope| {
            let login = scope.spawn(|| service.handle("POST", "/sessions", &alice(), "").0);

            // The login is now parked inside the hook. Replace the account: delete it
            // with the token it holds, then register the same username again, which
            // leaves a brand new account holding no session at all.
            paused.wait();
            let old_token = service.users.lock().unwrap()["alice"]
                .token
                .clone()
                .unwrap();
            assert_eq!(
                service
                    .handle(
                        "DELETE",
                        "/users/me",
                        &Value::Null,
                        &format!("Bearer {old_token}")
                    )
                    .0,
                200
            );
            assert_eq!(service.handle("POST", "/users", &alice(), "").0, 201);
            assert!(service.users.lock().unwrap()["alice"].token.is_none());

            // Let the stale login finish: it must refuse rather than attach a session
            // to an account it never authenticated against.
            resume.wait();
            assert_eq!(login.join().unwrap(), 401);
        });

        // The decisive check: the recreated account still holds no token, so nobody
        // is logged in through the stale login. Had it applied, a token would exist
        // here and `sign_up` would hand out that very token.
        assert!(service.users.lock().unwrap()["alice"].token.is_none());

        // The recreated account is reachable by logging in again (it is already
        // registered), and the texts of the deleted account are gone with it.
        let login = service.handle("POST", "/sessions", &alice(), "").1;
        let auth = format!("Bearer {}", login["data"]["token"].as_str().unwrap());
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &auth),
            (200, json!({"data": []}))
        );
    }

    #[test]
    fn users_cannot_reach_each_others_texts() {
        let service = Service::default();
        let a = sign_up(&service, &alice());
        let b = sign_up(
            &service,
            &json!({"username": "bob", "password": "password1"}),
        );

        // The same name belongs to each user separately.
        assert_eq!(
            service
                .handle("PUT", "/texts/note", &json!({"text": "from-alice"}), &a)
                .0,
            200
        );
        assert_eq!(
            service
                .handle("PUT", "/texts/note", &json!({"text": "from-bob"}), &b)
                .0,
            200
        );
        assert_eq!(
            service
                .handle("PUT", "/texts/private", &json!({"text": "alice-only"}), &a)
                .0,
            200
        );

        assert_eq!(
            service.handle("GET", "/texts/note", &Value::Null, &a),
            (200, json!({"data": "from-alice"}))
        );
        assert_eq!(
            service.handle("GET", "/texts/note", &Value::Null, &b),
            (200, json!({"data": "from-bob"}))
        );

        // A text that exists but belongs to someone else must be indistinguishable
        // from one that does not exist at all.
        assert_eq!(
            service.handle("GET", "/texts/private", &Value::Null, &b).0,
            404
        );

        // Listings are per user.
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &a),
            (200, json!({"data": ["note", "private"]}))
        );
        assert_eq!(
            service.handle("GET", "/texts", &Value::Null, &b),
            (200, json!({"data": ["note"]}))
        );

        // Writing under a name bob also owns changes alice's own copy only.
        assert_eq!(
            service
                .handle("PUT", "/texts/note", &json!({"text": "alice-again"}), &a)
                .0,
            200
        );
        assert_eq!(
            service.handle("GET", "/texts/note", &Value::Null, &b),
            (200, json!({"data": "from-bob"}))
        );
    }
}
