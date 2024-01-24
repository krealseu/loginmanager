use std::rc::Rc;

use actix_web::{
    get,
    web::{self, Redirect},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use axum::async_trait;
use db::User;
use loginmanager::{AuthContext, AuthUser, CookieSession, CurrentUser, LoginManager};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement, Value};
use serde::Deserialize;
mod db;

#[async_trait(?Send)]
impl loginmanager::UserMinix<HttpRequest> for User {
    type Key = i32;
    async fn get_user2(id: &Self::Key, req: &mut HttpRequest) -> Option<Self> {
        let db = req.app_data::<web::Data<DatabaseConnection>>()?;

        let user = db
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

#[get("/")]
async fn index(AuthUser(user): AuthUser<User>) -> HttpResponse {
    HttpResponse::Ok().content_type("text/html").body(format!(
        "Hello:{:?} <br> <a href='/logout'>logout</a>",
        user.name,
    ))
}

async fn login_get() -> HttpResponse {
    HttpResponse::Ok().body(
        r#"
    <form method="POST">
        username:<input name="username"></input>
        password:<input name="password" type="password"></input>
        <input type="submit"></input>
    </form>
    "#,
    )
}

#[derive(Deserialize)]
struct UserForm {
    username: String,
    password: String,
}

async fn login_post(
    mut auth_context: AuthContext,
    db: web::Data<DatabaseConnection>,
    form: web::Form<UserForm>,
) -> HttpResponse {
    let user = db
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
            return HttpResponse::SeeOther()
                .insert_header(("location", "/"))
                .body("/");
        } else {
            return HttpResponse::Ok().body("error password");
        }
    } else {
        return HttpResponse::Ok().body(format!("{:?} not exists.", user));
    }
}

async fn login_out(
    mut auth_context: AuthContext,
    CurrentUser(user): CurrentUser<User>,
) -> HttpResponse {
    auth_context.logout();
    HttpResponse::SeeOther()
        .insert_header(("location", "/login"))
        .body("/")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let conn = db::get_db().await;
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(conn.clone()))
            .wrap(LoginManager::new(
                CookieSession::new("secret").secure(false),
            ))
            .service(index)
            .route("/login", web::get().to(login_get))
            .route("/login", web::post().to(login_post))
            .route("/logout", web::get().to(login_out))
        // .service(echo)
        // .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
