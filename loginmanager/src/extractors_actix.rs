use crate::{loginmanager::LoginInfo, AuthContext, AuthUser, CurrentUser, UserMinix};
use actix_web::{error::InternalError, Error, HttpMessage};
use futures_util::future::LocalBoxFuture;

impl<T> actix_web::FromRequest for CurrentUser<Option<T>>
where
    T: UserMinix<actix_web::HttpRequest> + Clone + Send + Sync + 'static,
{
    type Error = Error;

    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let req_clone = req.clone();
        let mut req_clone2 = req.clone();
        Box::pin(async move {
            let extensions = &mut req_clone.extensions_mut();
            if let Some(u) = extensions.get::<T>() {
                return Ok(Self(Some(u.to_owned())));
            }
            if let Some(info) = extensions.get::<LoginInfo>() {
                if let Some(key) = info.get_key() {
                    if let Ok(key) = serde_json::from_str::<T::Key>(&key) {
                        let real_user = T::get_user2(&key, &mut req_clone2).await;
                        if let Some(u) = real_user {
                            extensions.insert(u.to_owned());
                            return Ok(Self(Some(u.to_owned())));
                        }
                    }
                }
                Ok(Self(None))
            } else {
                Err(InternalError::new(
                    "please use loginmanger middleware first",
                    actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                )
                .into())
            }
        })
    }
}

impl<T> actix_web::FromRequest for CurrentUser<T>
where
    T: UserMinix<actix_web::HttpRequest> + Clone + Send + Sync + 'static,
{
    type Error = Error;

    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let fut = CurrentUser::<Option<T>>::from_request(req, payload);
        Box::pin(async move {
            fut.await?.0.map(Into::into).ok_or(
                InternalError::new(
                    "No authentication.",
                    actix_web::http::StatusCode::UNAUTHORIZED,
                )
                .into(),
            )
        })
    }
}

impl<T> actix_web::FromRequest for AuthUser<Option<T>>
where
    T: UserMinix<actix_web::HttpRequest> + Clone + Send + Sync + 'static,
{
    type Error = Error;

    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let fut = CurrentUser::<Option<T>>::from_request(req, payload);
        Box::pin(async move {
            let user = fut.await?.0;
            match user {
                None => Ok(Self(None)),
                Some(user) => {
                    if user.is_actived() && user.is_authenticated() {
                        Ok(Self(Some(user.to_owned())))
                    } else {
                        Err(InternalError::new(
                            "No authentication.",
                            actix_web::http::StatusCode::UNAUTHORIZED,
                        )
                        .into())
                    }
                }
            }
        })
    }
}

impl<T> actix_web::FromRequest for AuthUser<T>
where
    T: UserMinix<actix_web::HttpRequest> + Clone + Send + Sync + 'static,
{
    type Error = Error;

    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let f = CurrentUser::<T>::from_request(req, payload);
        Box::pin(async move {
            let user = f.await?.0;
            if user.is_actived() && user.is_authenticated() {
                Ok(Self(user.to_owned()))
            } else {
                Err(InternalError::new(
                    "No authentication.",
                    actix_web::http::StatusCode::UNAUTHORIZED,
                )
                .into())
            }
        })
    }
}

impl actix_web::FromRequest for AuthContext {
    type Error = actix_web::Error;

    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            req.extensions().get::<LoginInfo>().map(Into::into).ok_or(
                InternalError::new(
                    "please use loginmanger middleware first",
                    actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                )
                .into(),
            )
        })
    }
}
