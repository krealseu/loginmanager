use async_trait::async_trait;
use std::sync::{Arc, RwLock};

#[allow(unused)]
#[async_trait]
pub trait DecodeRequest: Sized + Sync + Send {
    type Request;

    type Response;

    async fn decode(&self, req: &Self::Request, login_info: &LoginInfo) -> Option<String>;

    async fn update_(&self, res: &mut Self::Response, login_info: &LoginInfo);
}

#[derive(Debug, Clone)]
pub enum State {
    Init,
    Ok,
    Login(String),
    Update(String),
    Logout,
    Err,
}

#[derive(Debug)]
struct LoginInfoInner {
    pub key_str: Option<String>,
    pub state: State,
    pub ext: Option<String>,
}

impl Default for LoginInfoInner {
    fn default() -> Self {
        Self {
            key_str: None,
            state: State::Init,
            ext: None,
        }
    }
}

impl LoginInfoInner {
    pub fn login(&mut self, key_str: String) {
        // self.key_str = Some(key_str);
        self.state = State::Login(key_str);
    }

    pub fn logout(&mut self) {
        self.key_str = None;
        self.state = State::Logout;
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

    pub(crate) fn key_str(&self) -> Option<String> {
        self.0.read().unwrap().key_str.clone()
    }

    pub(crate) fn set_key_str(&self, key_str: Option<String>) {
        self.0.write().unwrap().key_str = key_str;
    }

    pub fn state(&self) -> State {
        self.0.read().unwrap().state.clone()
    }

    pub fn set_state(&self, state: State) {
        self.0.write().unwrap().state = state;
    }

    pub fn ext(&self) -> Option<String> {
        self.0.read().unwrap().ext.clone()
    }

    pub fn set_ext(&self, ext: Option<String>) {
        self.0.write().unwrap().ext = ext;
    }
}

pub struct Inner<D>
where
    D: DecodeRequest,
{
    pub(crate) decoder: D,
    pub(crate) login_view: String,
    pub(crate) redirect: bool,
}

impl<D> Inner<D>
where
    D: DecodeRequest,
{
    pub fn redirect(&self) -> bool {
        self.redirect
    }
}

/// LoginManager<D> is implemented as a middleware.   
/// - `D` the type of DecodeRequest. It decode the key_string from request.  
#[derive(Clone)]
pub struct LoginManager<D>(pub(crate) Arc<Inner<D>>)
where
    D: DecodeRequest;

impl<D> LoginManager<D>
where
    D: DecodeRequest,
{
    pub fn new(decoder: D) -> Self
    where
        D: DecodeRequest,
    {
        Self(Arc::new(Inner {
            decoder,
            login_view: "/login".to_owned(),
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
}
