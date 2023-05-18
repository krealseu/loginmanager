use async_trait::async_trait;
#[cfg(feature = "axum_layer")]
use axum::{body::Body, response::Response};
use cookie::{Cookie, CookieJar, Key, SameSite};
use http::{header, Request};

use headers::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crypto::{digest::Digest, sha2::Sha256};

use crate::loginmanager::{DecodeRequest, LoginInfo, State};

/// use cookie as session to storage the info of user key.
#[derive(Clone)]
pub struct CookieSession {
    key: Key,
    name: String,
    path: String,
    domain: Option<String>,
    secure: bool,
    http_only: bool,
    max_age: Option<Duration>,
    expires_in: Option<Duration>,
    same_site: Option<SameSite>,
}

impl CookieSession {
    /// The key must be at least 256-bits (32 bytes).  
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: Key::derive_from(key),
            name: "_session".to_owned(),
            path: "/".to_owned(),
            domain: None,
            secure: true,
            http_only: true,
            max_age: None,
            expires_in: None,
            same_site: None,
        }
    }

    pub fn name(mut self, name: &'static str) -> Self {
        self.name = name.to_owned();
        self
    }

    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    pub fn domain(mut self, domain: Option<String>) -> Self {
        self.domain = domain;
        self
    }

    pub fn max_age(mut self, max_age: Option<Duration>) -> Self {
        self.max_age = max_age;
        self
    }

    pub fn expires_in(mut self, expires_in: Option<Duration>) -> Self {
        self.expires_in = expires_in;
        self
    }

    pub fn same_site(mut self, same_site: Option<SameSite>) -> Self {
        self.same_site = same_site;
        self
    }

    fn get_session_from(&self, headers: &HeaderMap<HeaderValue>) -> Option<Session> {
        let mut cookie_find = "".to_owned();
        for hdr in headers.get_all(header::COOKIE) {
            let s = hdr.to_str().unwrap();
            for cookie_str in s.split(';').map(|s| s.trim()) {
                if !cookie_str.is_empty() && cookie_str.starts_with(&format!("{}=", self.name)) {
                    cookie_find = cookie_str.to_string();
                }
            }
        }
        match Cookie::parse_encoded(cookie_find) {
            Ok(cookie) => {
                let mut jar = CookieJar::new();
                jar.add_original(cookie.clone());
                if let Some(cookie) = jar.private(&self.key).get(&self.name) {
                    serde_json::from_str::<Session>(cookie.value()).ok()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn create_cookie(&self, session: Session) -> CookieJar {
        let value = serde_json::to_string(&session).map_err(|_| "").unwrap();
        let mut cookie = Cookie::new(self.name.clone(), value);
        cookie.set_path(self.path.clone());
        cookie.set_secure(self.secure);
        cookie.set_http_only(self.http_only);

        if let Some(ref domain) = self.domain {
            cookie.set_domain(domain.clone());
        }

        if let Some(expires_in) = self.expires_in {
            cookie.set_expires(OffsetDateTime::now_utc() + expires_in);
        }

        if let Some(max_age) = self.max_age {
            cookie.set_max_age(max_age);
        }

        if let Some(same_site) = self.same_site {
            cookie.set_same_site(same_site);
        }
        let mut jar = CookieJar::new();
        jar.private_mut(&self.key).add(cookie);
        jar
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Session {
    id: String,
    user_id: Option<String>,
}

#[cfg(feature = "axum_layer")]
impl CookieSession {
    fn _create_identifier(header: &HeaderMap<HeaderValue>) -> String {
        let mut hasher: Sha256 = Sha256::new();
        hasher.input_str("loginmanager");
        if let Some(agent) = header.get(header::USER_AGENT) {
            if let Ok(agent) = agent.to_str() {
                hasher.input_str(agent);
            } else {
                hasher.input_str("agent-fake");
            };
        };
        if let Some(agent) = header.get(header::HOST) {
            if let Ok(agent) = agent.to_str() {
                hasher.input_str(agent);
            } else {
                hasher.input_str("host-fake");
            };
        };
        return hasher.result_str();
    }
}

#[cfg(feature = "axum_layer")]
#[async_trait]
impl DecodeRequest for CookieSession {
    type Request = Request<Body>;

    type Response = Response;

    async fn decode(&self, req: &Self::Request, login_info: &LoginInfo) -> Option<String> {
        let session = self.get_session_from(req.headers());
        session.map_or(None, |s| {
            let id = Self::_create_identifier(req.headers());
            if s.id == id {
                login_info.set_ext(Some(id));
                s.user_id
            } else {
                login_info.set_ext(Some(id));
                None
            }
        })
    }

    async fn update_(&self, res: &mut Self::Response, login_info: &LoginInfo) {
        let key = match login_info.state() {
            State::Login(key) => Some(key),
            State::Update(key) => Some(key),
            State::Logout => None,
            _ => return,
        };

        let id = login_info
            .ext()
            .unwrap_or(Self::_create_identifier(res.headers()));
        let session = Session { id, user_id: key };

        let jar = self.create_cookie(session);

        for i in jar.delta() {
            res.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&i.encoded().to_string()).unwrap(),
            );
        }
    }
}
