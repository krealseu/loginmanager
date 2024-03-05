use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

use crate::{loginmanager::LoginInfo, AuthContext, AuthUser, CurrentUser, UserMinix};

#[async_trait]
impl<S, T> FromRequestParts<S> for CurrentUser<Option<T>>
where
    S: Send + Sync,
    T: UserMinix<Parts> + Clone + Send + Sync + 'static,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        if let Some(u) = parts.extensions.get::<T>() {
            return Ok(Self(Some(u.to_owned())));
        }
        if let Some(info) = parts.extensions.get::<LoginInfo>() {
            if let Some(key) = info.key_str() {
                if let Ok(key) = serde_json::from_str::<T::Key>(&key) {
                    let real_user = T::get_user(&key, parts).await;
                    if let Some(real_user) = real_user {
                        parts.extensions.insert(real_user.to_owned());
                        return Ok(Self(Some(real_user.to_owned())));
                    }
                }
            }
            Ok(Self(None))
        } else {
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "please use loginmanger middleware first",
            ))
        }
    }
}

#[async_trait]
impl<S, T> FromRequestParts<S> for CurrentUser<T>
where
    S: Send + Sync,
    T: UserMinix<Parts> + Clone + Send + Sync + 'static,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        CurrentUser::<Option<T>>::from_request_parts(parts, state)
            .await?
            .0
            .map(Into::into)
            .ok_or((StatusCode::UNAUTHORIZED, "No authentication."))
    }
}

#[async_trait]
impl<S, T> FromRequestParts<S> for AuthUser<Option<T>>
where
    S: Send + Sync,
    T: UserMinix<Parts> + Clone + Send + Sync + 'static,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let u = CurrentUser::<Option<T>>::from_request_parts(parts, state)
            .await?
            .0;
        match u {
            None => Ok(Self(None)),
            Some(u) => {
                if u.is_actived() && u.is_authenticated() {
                    Ok(Self(Some(u.to_owned())))
                } else {
                    Err((StatusCode::UNAUTHORIZED, "No authentication."))
                }
            }
        }
    }
}

#[async_trait]
impl<S, T> FromRequestParts<S> for AuthUser<T>
where
    S: Send + Sync,
    T: UserMinix<Parts> + Clone + Send + Sync + 'static,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let u = CurrentUser::<T>::from_request_parts(parts, state).await?.0;
        if u.is_actived() && u.is_authenticated() {
            Ok(Self(u.to_owned()))
        } else {
            Err((StatusCode::UNAUTHORIZED, "No authentication."))
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<LoginInfo>().map(Into::into).ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "please use loginmanger middleware first",
        ))
    }
}
