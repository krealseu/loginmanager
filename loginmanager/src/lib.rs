#![cfg_attr(not(doctest), doc = include_str!("../README.md"))]

mod cooke_session;
mod extractors;
#[cfg(feature = "actix_layer")]
mod extractors_actix;
#[cfg(feature = "axum_layer")]
mod extractors_axum;
mod loginmanager;
#[cfg(feature = "actix_layer")]
mod loginmanager_actix;
#[cfg(feature = "axum_layer")]
mod loginmanager_axum;
// mod loginrequired;
pub use cooke_session::CookieSession;
pub use extractors::{AuthContext, AuthUser, CurrentUser, UserMinix};
pub use loginmanager::{DecodeRequest, LoginInfo, LoginManager};
// pub use loginrequired::LoginRequired;
