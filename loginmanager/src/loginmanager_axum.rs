use axum::{
    body::Body,
    http::Request,
    response::{IntoResponse, Redirect, Response},
};
use futures_util::future::BoxFuture;
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower_service::Service;

use crate::{
    loginmanager::{DecodeRequest, Inner, LoginInfo},
    LoginManager,
};

impl<S, D> tower_layer::Layer<S> for LoginManager<D> {
    type Service = LoginManagerMiddleware<S, D>;

    fn layer(&self, serv: S) -> Self::Service {
        LoginManagerMiddleware {
            serv,
            manager: self.0.clone(),
        }
    }
}

#[derive(Clone)]
pub struct LoginManagerMiddleware<S, D> {
    serv: S,
    manager: Arc<Inner<D>>,
}

impl<S, D> LoginManagerMiddleware<S, D> {
    pub(crate) fn loginmanger(&self) -> Arc<Inner<D>> {
        self.manager.clone()
    }
}

impl<S, D> Service<Request<Body>> for LoginManagerMiddleware<S, D>
where
    S: Service<Request<Body>, Response = Response> + Send + Sync + Clone + 'static,
    S::Future: Send + 'static,
    D: DecodeRequest<Request<Body>, Response> + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.serv.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let _serv = self.serv.clone();
        let mut serv = std::mem::replace(&mut self.serv, _serv);
        let redirect_url = if self.manager.redirect {
            req.uri().path_and_query().map(|f| f.to_string())
        } else {
            None
        };
        let manager = self.loginmanger();
        let logininfo = LoginInfo::default();
        req.extensions_mut().insert(logininfo.clone());

        Box::pin(async move {
            match manager.decoder.decode(&mut req).await {
                Ok(key) => logininfo.set_key(key),
                Err(res) => return Ok(res),
            };
            let mut res = serv.call(req).await?;
            // important for axum
            res.extensions_mut().insert(logininfo);
            manager.decoder.update(&mut res).await;

            if manager.redirect && res.status().as_u16() == 401 {
                let uri = if let Some(uri) = redirect_url {
                    manager.next_to(&uri)
                } else {
                    manager.next_to("/")
                };
                return Ok(Redirect::to(&uri).into_response());
            };
            Ok(res)
        })
    }
}
