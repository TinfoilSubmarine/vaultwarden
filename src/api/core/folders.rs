use axum::{
    Json,
    Router,
    routing::{get, post, put, delete},
};
use serde_json::Value;

use crate::{
    api::{EmptyResult, JsonResult, JsonUpcase, Notify, UpdateType},
    auth::Headers,
    db::{models::*, DbConn},
};

pub fn routes() -> Router {
    Router::new()
        .route("/folders", get(get_folders))
        .route("/folders/:uuid", get(get_folder))
        .route("/folders", post(post_folders))
        .route("/folders/:uuid", post(post_folder))
        .route("/folders/:uuid", put(put_folder))
        .route("/folders/:uuid/delete", post(delete_folder_post))
        .route("/folders/:uuid", delete(delete_folder))
}

async fn get_folders(headers: Headers, conn: DbConn) -> Json<Value> {
    let folders = Folder::find_by_user(&headers.user.uuid, &conn).await;
    let folders_json: Vec<Value> = folders.iter().map(Folder::to_json).collect();

    Json(json!({
      "Data": folders_json,
      "Object": "list",
      "ContinuationToken": null,
    }))
}

async fn get_folder(uuid: String, headers: Headers, conn: DbConn) -> JsonResult {
    let folder = match Folder::find_by_uuid(&uuid, &conn).await {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    Ok(Json(folder.to_json()))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct FolderData {
    pub Name: String,
}

async fn post_folders(data: JsonUpcase<FolderData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    let data: FolderData = data.into_inner().data;

    let mut folder = Folder::new(headers.user.uuid, data.Name);

    folder.save(&conn).await?;
    nt.send_folder_update(UpdateType::FolderCreate, &folder);

    Ok(Json(folder.to_json()))
}

async fn post_folder(
    uuid: String,
    data: JsonUpcase<FolderData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    put_folder(uuid, data, headers, conn, nt).await
}

async fn put_folder(
    uuid: String,
    data: JsonUpcase<FolderData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let data: FolderData = data.into_inner().data;

    let mut folder = match Folder::find_by_uuid(&uuid, &conn).await {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    folder.name = data.Name;

    folder.save(&conn).await?;
    nt.send_folder_update(UpdateType::FolderUpdate, &folder);

    Ok(Json(folder.to_json()))
}

async fn delete_folder_post(uuid: String, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    delete_folder(uuid, headers, conn, nt).await
}

async fn delete_folder(uuid: String, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let folder = match Folder::find_by_uuid(&uuid, &conn).await {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    // Delete the actual folder entry
    folder.delete(&conn).await?;

    nt.send_folder_update(UpdateType::FolderDelete, &folder);
    Ok(())
}
