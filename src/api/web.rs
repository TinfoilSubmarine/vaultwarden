use std::path::{Path, PathBuf};

use tower_http::services::ServeFile;
use mime::Mime;
use axum::{
    Json,
    Router,
    routing::get,
};
use serde_json::Value;

use crate::{
    error::Error,
    util::{Cached, SafeString},
    CONFIG,
};

pub fn routes() -> Router {
    // If addding more routes here, consider also adding them to
    // crate::utils::LOGGED_ROUTES to make sure they appear in the log
    if CONFIG.web_vault_enabled() {
        Router::new()
            .route("/", get(web_index))
            .route("/app-id.json", get(app_id))
            .route("/*p", get(web_files)) // Only match this if the other routes don't match
            .route("/attachments/:uuid/:file_id", get(attachments))
            .route("/alive", get(alive))
            .route("/vw_static/:filename", get(static_files))
    } else {
        Router::new()
            .route("/attachments/:uuid/:file_id", get(attachments))
            .route("/alive", get(alive))
            .route("/vw_static/:filename", get(static_files))
    }
}

async fn web_index() -> Cached<Option<ServeFile>> {
    Cached::short(ServeFile::new(Path::new(&CONFIG.web_vault_folder()).join("index.html")).await.ok(), false)
}

fn app_id() -> Cached<(Mime, Json<Value>)> {
    let content_type = "application/fido.trusted-apps+json";

    Cached::long(
        (
            content_type,
            Json(json!({
            "trustedFacets": [
                {
                "version": { "major": 1, "minor": 0 },
                "ids": [
                    // Per <https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html#determining-the-facetid-of-a-calling-application>:
                    //
                    // "In the Web case, the FacetID MUST be the Web Origin [RFC6454]
                    // of the web page triggering the FIDO operation, written as
                    // a URI with an empty path. Default ports are omitted and any
                    // path component is ignored."
                    //
                    // This leaves it unclear as to whether the path must be empty,
                    // or whether it can be non-empty and will be ignored. To be on
                    // the safe side, use a proper web origin (with empty path).
                    &CONFIG.domain_origin(),
                    "ios:bundle-id:com.8bit.bitwarden",
                    "android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI" ]
                }]
            })),
        ),
        true,
    )
}

async fn web_files(p: PathBuf) -> Cached<Option<ServeFile>> {
    Cached::long(ServeFile::new(Path::new(&CONFIG.web_vault_folder()).join(p)).await.ok(), true)
}

async fn attachments(uuid: SafeString, file_id: SafeString) -> Option<ServeFile> {
    ServeFile::new(Path::new(&CONFIG.attachments_folder()).join(uuid).join(file_id)).await.ok()
}

// We use DbConn here to let the alive healthcheck also verify the database connection.
use crate::db::DbConn;
fn alive(_conn: DbConn) -> Json<String> {
    use crate::util::format_date;
    use chrono::Utc;

    Json(format_date(&Utc::now().naive_utc()))
}

fn static_files(filename: String) -> Result<(mime::Mime, &'static [u8]), Error> {
    match filename.as_ref() {
        "mail-github.png" => Ok((mime::IMAGE_PNG, include_bytes!("../static/images/mail-github.png"))),
        "logo-gray.png" => Ok((mime::IMAGE_PNG, include_bytes!("../static/images/logo-gray.png"))),
        "error-x.svg" => Ok((mime::SVG, include_bytes!("../static/images/error-x.svg"))),
        "hibp.png" => Ok((mime::IMAGE_PNG, include_bytes!("../static/images/hibp.png"))),
        "vaultwarden-icon.png" => Ok((mime::IMAGE_PNG, include_bytes!("../static/images/vaultwarden-icon.png"))),
        "bootstrap.css" => Ok((mime::TEXT_CSS, include_bytes!("../static/scripts/bootstrap.css"))),
        "bootstrap-native.js" => Ok((mime::JAVASCRIPT, include_bytes!("../static/scripts/bootstrap-native.js"))),
        "identicon.js" => Ok((mime::JAVASCRIPT, include_bytes!("../static/scripts/identicon.js"))),
        "datatables.js" => Ok((mime::JAVASCRIPT, include_bytes!("../static/scripts/datatables.js"))),
        "datatables.css" => Ok((mime::TEXT_CSS, include_bytes!("../static/scripts/datatables.css"))),
        "jquery-3.6.0.slim.js" => {
            Ok((mime::JAVASCRIPT, include_bytes!("../static/scripts/jquery-3.6.0.slim.js")))
        }
        _ => err!(format!("Static file not found: {}", filename)),
    }
}
