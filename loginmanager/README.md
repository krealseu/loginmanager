# loginmanager
a simple loginmanager for axum

# Usage example
```rust
use std::sync::Arc;

use axum::{
    async_trait,
    http::request::Parts,
    middleware::from_extractor,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Extension, Form, Router,
};
use loginmanager::{AuthContext, AuthUser, CookieSession, CurrentUser, LoginManager};
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement, Value};
use serde::Deserialize;

#[derive(Debug, Clone)]
struct User {
    id: i32,
    name: String,
    password: String,
}

#[async_trait]
impl loginmanager::UserMinix<Parts> for User {
    type Key = i32;

    async fn get_user(id: &Self::Key, req: &mut Parts) -> Option<Self> {
        let state = req.extensions.get::<Arc<AppState>>()?;
        let user = state
            .db()
            .query_one(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "select id,name,password from user where id=?",
                [Value::from(id.to_string())],
            ))
            .await
            .ok()??;
        let user = Self {
            id: user.try_get::<i32>("", "id").unwrap(),
            name: user.try_get::<String>("", "name").unwrap(),
            password: user.try_get::<String>("", "password").unwrap(),
        };
        Some(user)
    }

    fn get_id(&self) -> &Self::Key {
        &self.id
    }
}

async fn hello_user(AuthUser(user): AuthUser<User>) -> Response {
    return Html(format!(
        "hello {}<br> <a href='/logout'>logout</a>",
        user.name
    ))
    .into_response();
}

async fn login_get() -> impl IntoResponse {
    return Html(
        r#"
    <form method="POST">
        username:<input name="username"></input>
        password:<input name="password" type="password"></input>
        <input type="submit"></input>
    </form>
    "#,
    );
}

#[derive(Deserialize)]
struct UserForm {
    username: String,
    password: String,
}

async fn login_post(
    Extension(state): Extension<Arc<AppState>>,
    mut auth_context: AuthContext,
    Form(form): Form<UserForm>,
) -> Response {
    let user = state
        .db()
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "select id,name,password from user where name=?",
            [Value::from(&form.username)],
        ))
        .await
        .ok()
        .unwrap();
    if let Some(user) = user {
        let user = User {
            id: user.try_get::<i32>("", "id").unwrap(),
            name: user.try_get::<String>("", "name").unwrap(),
            password: user.try_get::<String>("", "password").unwrap(),
        };
        if user.password == form.password {
            auth_context.login(&user);
            return Redirect::to("/").into_response();
        } else {
            return format!("error password").into_response();
        }
    } else {
        return format!("{:?} not exists.", user).into_response();
    }
}

async fn login_out(
    mut auth_context: AuthContext,
    CurrentUser(user): CurrentUser<User>,
) -> impl IntoResponse {
    auth_context.logout();
    return Redirect::to("/login");
}

pub struct AppState {
    conn: DatabaseConnection,
}

impl AppState {
    pub fn db(&self) -> &DatabaseConnection {
        &self.conn
    }
}

#[tokio::main]
async fn main() {
    // protect api
    let api = Router::new()
        .route("/:path", get(hello_user))
        .route_layer(from_extractor::<AuthUser<User>>());

    let loginmanager = LoginManager::new(CookieSession::new(&[8; 32]))
        .redirect(true)
        .login_view("/login");

    let conn: DatabaseConnection = Database::connect("sqlite::memory:").await.unwrap();
    conn.execute(Statement::from_string(
        DatabaseBackend::Sqlite,
        r#"
        CREATE TABLE "user" (
            "id"	INTEGER,
            "name"	TEXT UNIQUE,
            "password"	TEXT,
            PRIMARY KEY("id")
        );
        INSERT INTO user VALUES (1,"miku","39"),(2,"miku2","392");
        "#
        .to_owned(),
    ))
    .await
    .unwrap();

    let app = Router::new()
        .nest("/api", api)
        .route("/", get(hello_user))
        .route("/login", get(login_get).post(login_post))
        .route("/logout", get(login_out))
        .route("/common", get(|| async { "Hello, World!" }))
        .layer(loginmanager)
        .layer(Extension(Arc::new(AppState { conn })));

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```