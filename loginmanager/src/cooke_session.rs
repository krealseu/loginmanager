#[cfg(feature = "actix_layer")]
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    HttpMessage,
};
use async_trait::async_trait;
#[cfg(feature = "axum_layer")]
use axum::{body::Body, response::Response};
use cookie::{Cookie, CookieJar, Key, SameSite};
use http::{header, HeaderMap, HeaderValue, Request};
use sha2::digest::FixedOutput;
use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::loginmanager::{DecodeRequest, LoginInfo};

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
    pub fn new(key: &str) -> Self {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(key);
        let key = hasher.finalize_fixed();
        Self {
            key: Key::derive_from(&key),
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

    /// Set cookie name, Default: `_session`
    pub fn name(mut self, name: &'static str) -> Self {
        self.name = name.to_owned();
        self
    }

    pub fn path(mut self, path: String) -> Self {
        self.path = path;
        self
    }

    /// Cookie requires Secure or not, Default `true`
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Cookie uses HttpOnly or not, Default `true`
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    pub fn domain(mut self, domain: Option<String>) -> Self {
        self.domain = domain;
        self
    }

    /// Cookie expires, Default: 30 days
    pub fn duration(mut self, max_age: Option<Duration>) -> Self {
        self.max_age = max_age;
        self
    }

    /// Cookie requires same origin, Default `None`
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

impl CookieSession {
    #[cfg(feature = "axum_layer")]
    fn _create_identifier(header: &HeaderMap<HeaderValue>) -> String {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update("loginmanager");
        if let Some(agent) = header.get(header::USER_AGENT) {
            if let Ok(agent) = agent.to_str() {
                hasher.update(agent);
            } else {
                hasher.update("agent-fake");
            };
        };
        if let Some(host) = header.get(header::HOST) {
            if let Ok(agent) = host.to_str() {
                hasher.update(agent);
            } else {
                hasher.update("host-fake");
            };
        };
        return hex::encode(hasher.finalize_fixed());
    }

    #[cfg(feature = "actix_layer")]
    fn _create_identifier_actix(request: &actix_web::HttpRequest) -> String {
        let mut hasher = Sha256::new();
        if let Some(addr) = request.connection_info().realip_remote_addr() {
            if let Some(ip) = addr.split(":").next() {
                hasher.update(ip);
            };
        }
        if let Some(agent) = request.headers().get(actix_web::http::header::USER_AGENT) {
            if let Ok(agent) = agent.to_str() {
                hasher.update(agent);
            };
        };
        return hex::encode(hasher.finalize_fixed());
    }
}

#[cfg(feature = "axum_layer")]
#[async_trait]
impl DecodeRequest<Request<Body>, Response> for CookieSession {
    async fn decode(&self, req: &mut Request<Body>) -> Result<Option<String>, Response> {
        let login_info = req.extensions().get::<LoginInfo>().unwrap();
        let session = self.get_session_from(req.headers());
        let id = Self::_create_identifier(req.headers());
        let res = Ok(session.map_or(None, |s| if s.id == id { s.user_id } else { None }));
        login_info.set_ext(Some(id));
        res
    }

    async fn update(&self, res: &mut Response) {
        let login_info = res.extensions().get::<LoginInfo>().unwrap();
        let key = if login_info.is_logout() {
            None
        } else if login_info.is_login() {
            login_info.login_key()
        } else {
            return;
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

#[cfg(feature = "actix_layer")]
#[async_trait(?Send)]
impl DecodeRequest<ServiceRequest, ServiceResponse> for CookieSession {
    async fn decode2(&self, req: &mut ServiceRequest) -> Result<Option<String>, ServiceResponse> {
        let mut cookie_find = "".to_owned();
        for hdr in req.headers().get_all(actix_web::http::header::COOKIE) {
            let s = hdr.to_str().unwrap();
            for cookie_str in s.split(';').map(|s| s.trim()) {
                if !cookie_str.is_empty() && cookie_str.starts_with(&format!("{}=", self.name)) {
                    cookie_find = cookie_str.to_string();
                }
            }
        }
        let session = match Cookie::parse_encoded(cookie_find) {
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
        };
        Ok(session.map_or(None, |s| {
            let id = Self::_create_identifier_actix(req.request());
            if s.id == id {
                s.user_id
            } else {
                None
            }
        }))
    }

    async fn update2(&self, res: &mut ServiceResponse) {
        let logininfo = res
            .request()
            .extensions()
            .get::<LoginInfo>()
            .unwrap()
            .clone();
        let key = if logininfo.is_logout() {
            None
        } else if logininfo.is_login() {
            logininfo.login_key()
        } else {
            return;
        };
        let session = Session {
            id: Self::_create_identifier_actix(res.request()),
            user_id: key,
        };

        let jar = self.create_cookie(session);

        for cookie in jar.delta() {
            let val = actix_web::http::header::HeaderValue::from_str(&cookie.encoded().to_string())
                .map_err(|_| ())
                .unwrap();
            res.headers_mut()
                .append(actix_web::http::header::SET_COOKIE, val);
        }
    }
}
