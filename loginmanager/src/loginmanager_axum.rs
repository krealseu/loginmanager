use axum::{
    body::Body,
    http::Request,
    response::{IntoResponse, Redirect, Response},
};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::{
    loginmanager::{DecodeRequest, Inner, LoginInfo, State},
    LoginManager,
};

impl<S, D> Layer<S> for LoginManager<D>
where
    D: DecodeRequest<Request = Request<Body>, Response = Response>,
{
    type Service = LoginManagerMiddleware<S, D>;

    fn layer(&self, inner: S) -> Self::Service {
        LoginManagerMiddleware {
            inner,
            loginmanger: self.0.clone(),
        }
    }
}

#[derive(Clone)]
pub struct LoginManagerMiddleware<S, D>
where
    D: DecodeRequest,
{
    inner: S,
    loginmanger: Arc<Inner<D>>,
}

impl<S, D> LoginManagerMiddleware<S, D>
where
    D: DecodeRequest,
{
    pub fn loginmanger(&self) -> Arc<Inner<D>> {
        self.loginmanger.clone()
    }
}

// #[derive(Clone)]
// pub struct LoginManagerMiddleware<S> {
//     inner: S,
// }

impl<S, D> Service<Request<Body>> for LoginManagerMiddleware<S, D>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
    D: DecodeRequest<Request = Request<Body>, Response = Response> + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let not_ready_inner = self.inner.clone();
        let mut ready_inner = std::mem::replace(&mut self.inner, not_ready_inner);
        let loginmanager = self.loginmanger();

        let redirect = self.loginmanger.redirect;
        Box::pin(async move {
            let redirect_url = if redirect {
                req.uri().path_and_query().map(|f| f.to_string())
            } else {
                None
            };
            let ext = req.extensions_mut();
            let logininfo = if let Some(e) = ext.get::<LoginInfo>() {
                e.clone()
            } else {
                let s = LoginInfo::default();
                ext.insert(s.clone());
                s
            };
            let key_str = loginmanager.decoder.decode(&req, &logininfo).await;
            logininfo.set_state(if key_str.is_none() {
                State::Err
            } else {
                State::Ok
            });
            logininfo.set_key_str(key_str);

            let mut res = ready_inner.call(req).await?;
            loginmanager.decoder.update_(&mut res, &logininfo).await;
            if redirect && res.status().as_u16() == 401 {
                let uri = if let Some(uri) = redirect_url {
                    uri.replace("&", "%26").replace("=", "%3d")
                } else {
                    "/".to_owned()
                };
                let uri = format!("{}?next={}", loginmanager.login_view, uri);
                return Ok(Redirect::to(&uri).into_response());
            };

            Ok(res)
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Session {
    id: String,
    user_id: Option<String>,
}
