use futures_util::future::{BoxFuture, LocalBoxFuture};
use serde::{de::DeserializeOwned, Serialize};

use crate::loginmanager::LoginInfo;

#[allow(unused)]
pub trait UserMinix<R>: Sized + Sync + Send + Clone {
    /// The type of User, must be same as Loginmanager.
    /// Otherwise no user will be returned.
    type Key: Serialize + DeserializeOwned + Send + Sync;

    /// Get user from id and req,Tip:can use req.app_data to obtain
    /// database connection defined in Web app.
    // async fn get_user(id: &Self::Key, req: &mut R) -> Option<Self>;
    fn get_user<'l1, 'l2, 'a>(id: &'l1 Self::Key, req: &'l2 mut R) -> BoxFuture<'a, Option<Self>>
    where
        'l1: 'a,
        'l2: 'a,
        Self: 'a,
    {
        Box::pin(async { None })
    }

    fn get_user2<'l1, 'l2, 'a>(
        id: &'l1 Self::Key,
        req: &'l2 mut R,
    ) -> LocalBoxFuture<'a, Option<Self>>
    where
        'l1: 'a,
        'l2: 'a,
        Self: 'a,
    {
        Box::pin(async { None })
    }

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

#[derive(Debug, Clone)]
pub struct AuthUser<T>(pub T);

#[derive(Debug)]
pub struct AuthContext(pub(crate) LoginInfo);

impl AuthContext {
    pub fn login<U, R>(&mut self, user: &U)
    where
        U: UserMinix<R>,
    {
        let key_str = serde_json::to_string(&user.get_id()).ok();
        self.0.login(key_str.unwrap());
    }

    pub fn logout(&mut self) {
        self.0.logout();
    }
}

impl From<&LoginInfo> for AuthContext {
    fn from(value: &LoginInfo) -> Self {
        Self(value.clone())
    }
}
