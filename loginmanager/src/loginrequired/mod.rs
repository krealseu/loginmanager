#[cfg(feature = "axum_layer")]
mod axum;

pub struct LoginRequired<U>(Option<U>);
