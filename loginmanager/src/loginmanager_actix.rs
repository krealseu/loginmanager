use std::{
    future::{ready, Ready},
    sync::Arc,
};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::{
        header::{HeaderValue, LOCATION},
        StatusCode,
    },
    Error, HttpMessage,
};
use futures_util::future::LocalBoxFuture;

use crate::{loginmanager::Inner, DecodeRequest, LoginInfo, LoginManager};

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S: 'static, B, D> Transform<S, ServiceRequest> for LoginManager<D>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    D: DecodeRequest<ServiceRequest, ServiceResponse<B>> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = LoginManagerMiddleware<S, D>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(LoginManagerMiddleware {
            service: Arc::new(service),
            loginmanger: self.0.clone(),
        }))
    }
}

#[derive(Clone)]
pub struct LoginManagerMiddleware<S, D> {
    service: Arc<S>,
    loginmanger: Arc<Inner<D>>,
}

impl<S, D> LoginManagerMiddleware<S, D> {
    pub(crate) fn loginmanger(&self) -> Arc<Inner<D>> {
        self.loginmanger.clone()
    }
}

impl<S, B, D> Service<ServiceRequest> for LoginManagerMiddleware<S, D>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    D: DecodeRequest<ServiceRequest, ServiceResponse<B>> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let serv = self.service.clone();

        let loginmanager = self.loginmanger();
        let logininfo = LoginInfo::default();
        req.extensions_mut().insert(logininfo.clone());

        Box::pin(async move {
            match loginmanager.decoder.decode2(&mut req).await {
                Ok(key) => logininfo.set_key(key),
                Err(res) => return Ok(res),
            };
            let mut res = serv.call(req).await?;
            loginmanager.decoder.update2(&mut res).await;

            if loginmanager.redirect && res.status().as_u16() == 401 {
                res.response_mut().head_mut().status = StatusCode::FOUND;
                let url = res
                    .request()
                    .uri()
                    .path_and_query()
                    .map_or("/".to_string(), |p| loginmanager.next_to(p.as_str()));
                let headervalue = HeaderValue::from_str(&url).unwrap();
                res.headers_mut().insert(LOCATION, headervalue);
            };
            Ok(res)
        })
    }
}
