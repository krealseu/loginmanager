use async_trait::async_trait;
#[cfg(feature = "axum_layer")]
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

use serde::{de::DeserializeOwned, Serialize};

use crate::loginmanager::LoginInfo;

#[async_trait]
pub trait UserMinix<R>: Sized + Sync + Send + Clone {
    /// The type of User, must be same as Loginmanager.
    /// Otherwise no user will be returned.
    type Key: Serialize + DeserializeOwned + Send + Sync;

    /// Get user from id and req,Tip:can use req.app_data to obtain
    /// database connection defined in Web app.
    async fn get_user(id: &Self::Key, req: &mut R) -> Option<Self>;

    /// Return the User id
    fn get_id(&self) -> &Self::Key;

    /// return user's actual authentication status, default True.
    fn is_authenticated(&self) -> bool {
        true
    }

    /// return user's actual active status, default True.
    fn is_actived(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct CurrentUser<T>(pub T);

#[cfg(feature = "axum_layer")]
#[async_trait]
impl<S, T> FromRequestParts<S> for CurrentUser<T>
where
    S: Send + Sync,
    T: UserMinix<Parts> + Clone + Send + Sync + 'static,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        if let Some(u) = parts.extensions.get::<T>() {
            return Ok(Self(u.to_owned()));
        }
        if let Some(info) = parts.extensions.get::<LoginInfo>() {
            if let Some(key) = info.key_str() {
                if let Ok(key) = serde_json::from_str::<T::Key>(&key) {
                    let real_user = T::get_user(&key, parts).await;
                    if let Some(real_user) = real_user {
                        parts.extensions.insert(Self(real_user.to_owned()));
                        return Ok(Self(real_user.to_owned()));
                    }
                }
            }
            Err((StatusCode::UNAUTHORIZED, "No authentication."))
        } else {
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "please use loginmanger middleware first",
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthUser<T>(pub T);

#[cfg(feature = "axum_layer")]
#[async_trait]
impl<S, T> FromRequestParts<S> for AuthUser<T>
where
    S: Send + Sync,
    T: UserMinix<Parts> + Clone + Send + Sync + 'static,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let unauthorized = (StatusCode::UNAUTHORIZED, "No authentication.");
        if let Some(u) = parts.extensions.get::<T>() {
            if u.is_actived() && u.is_authenticated() {
                return Ok(Self(u.to_owned()));
            } else {
                return Err(unauthorized);
            }
        }
        if let Some(info) = parts.extensions.get::<LoginInfo>() {
            if let Some(key) = info.key_str() {
                if let Ok(key) = serde_json::from_str::<T::Key>(&key) {
                    let real_user = T::get_user(&key, parts).await;
                    if let Some(u) = real_user {
                        parts.extensions.insert(Self(u.to_owned()));
                        if u.is_actived() && u.is_authenticated() {
                            return Ok(Self(u.to_owned()));
                        } else {
                            return Err(unauthorized);
                        }
                    }
                }
            }
            Err(unauthorized)
        } else {
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "please use loginmanger middleware first",
            ))
        }
    }
}

#[derive(Debug)]
pub struct AuthContext(LoginInfo);

impl AuthContext {
    pub fn login<U, R>(&mut self, user: &U)
    where
        R: Send,
        U: UserMinix<R>,
    {
        let key_str = serde_json::to_string(&user.get_id()).ok();
        self.0.login(key_str.unwrap());
    }

    pub fn logout(&mut self) {
        self.0.logout();
    }
}

#[cfg(feature = "axum_layer")]
#[async_trait]
impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<LoginInfo>()
            .map(|l| {
                let info = l.clone();
                Self(info)
            })
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "please use loginmanger middleware first",
            ))
    }
}
