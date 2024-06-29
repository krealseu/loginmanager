use futures::future::{BoxFuture, LocalBoxFuture};
use std::sync::{Arc, RwLock};

#[allow(unused)]
pub trait DecodeRequest<Req, Res>: Sized + Send {
    /// get user key
    fn decode<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: &'life1 mut Req,
    ) -> BoxFuture<'async_trait, Result<Option<String>, Res>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async { Ok(None) })
    }

    fn update<'life0, 'life1, 'async_trait>(
        &'life0 self,
        res: &'life1 mut Res,
    ) -> BoxFuture<'async_trait, ()>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async {})
    }

    fn decode2<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: &'life1 mut Req,
    ) -> LocalBoxFuture<'async_trait, Result<Option<String>, Res>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async { Ok(None) })
    }

    fn update2<'life0, 'life1, 'async_trait>(
        &'life0 self,
        res: &'life1 mut Res,
    ) -> LocalBoxFuture<'async_trait, ()>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async {})
    }
}

#[derive(Debug)]
struct LoginInfoInner {
    pub key_str: Option<String>,
    pub logout: bool,
    pub new_key: Option<String>,
    pub ext: Option<String>,
}

impl Default for LoginInfoInner {
    fn default() -> Self {
        Self {
            key_str: None,
            logout: false,
            new_key: None,
            ext: None,
        }
    }
}

impl LoginInfoInner {
    pub fn login(&mut self, key_str: String) {
        self.new_key = Some(key_str)
    }

    pub fn logout(&mut self) {
        self.key_str = None;
        self.logout = true;
    }
}

#[derive(Debug, Clone, Default)]
pub struct LoginInfo(Arc<RwLock<LoginInfoInner>>);

#[allow(dead_code)]
impl LoginInfo {
    pub fn login(&self, key_str: String) {
        self.0.write().unwrap().login(key_str);
    }

    pub fn logout(&self) {
        self.0.write().unwrap().logout();
    }

    pub(crate) fn get_key(&self) -> Option<String> {
        self.0.read().unwrap().key_str.clone()
    }

    pub(crate) fn set_key(&self, key_str: Option<String>) {
        self.0.write().unwrap().key_str = key_str;
    }

    pub fn login_key(&self) -> Option<String> {
        self.0.read().unwrap().new_key.clone()
    }

    /// new user login
    pub fn is_login(&self) -> bool {
        self.0.read().unwrap().new_key.is_some()
    }

    /// user had logout
    pub fn is_logout(&self) -> bool {
        self.0.read().unwrap().logout
    }

    pub fn ext(&self) -> Option<String> {
        self.0.read().unwrap().ext.clone()
    }

    pub fn set_ext(&self, ext: Option<String>) {
        self.0.write().unwrap().ext = ext;
    }
}

pub(crate) struct Inner<D> {
    pub(crate) decoder: D,
    pub(crate) login_view: String,
    pub(crate) next_key: String,
    pub(crate) redirect: bool,
}

impl<D> Inner<D> {
    /// get next uri
    pub fn next_to(&self, uri: &str) -> String {
        let uri = urlencoding::encode_binary(uri.as_bytes()).into_owned();
        format!("{}?{}={}", self.login_view, self.next_key, uri)
    }
}
/// LoginManager<D> is implemented as a middleware.
///
/// - `D` the type of DecodeRequest. It decode the key_string from request.
#[derive(Clone)]
pub struct LoginManager<D>(pub(crate) Arc<Inner<D>>);

impl<D> LoginManager<D> {
    pub fn new(decoder: D) -> Self {
        Self(Arc::new(Inner {
            decoder,
            login_view: "/login".to_owned(),
            next_key: "next".to_owned(),
            redirect: true,
        }))
    }

    /// Set false, not redirect when user is not authenticated. Default true.
    pub fn redirect(mut self, redirect: bool) -> Self {
        Arc::get_mut(&mut self.0).unwrap().redirect = redirect;
        self
    }

    /// Set the login url redirect, default '/login'.
    pub fn login_view<S: Into<String>>(mut self, login_view: S) -> Self {
        Arc::get_mut(&mut self.0).unwrap().login_view = login_view.into();
        self
    }

    /// Set the query `?next=/url`, default 'next'.
    pub fn next_key<S: Into<String>>(mut self, next_key: S) -> Self {
        Arc::get_mut(&mut self.0).unwrap().next_key = next_key.into();
        self
    }
}
