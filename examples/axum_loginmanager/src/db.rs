use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};

#[derive(Debug, Clone)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub password: String,
}

pub async fn get_db() -> DatabaseConnection {
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
    conn
}
