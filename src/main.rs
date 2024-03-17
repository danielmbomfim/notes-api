use std::collections::BTreeMap;

use dotenv::dotenv;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use rocket::{http::Status, response::status::Custom, serde::json::Json};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[macro_use]
extern crate rocket;

#[derive(Deserialize)]
struct GoogleAuthData<'a> {
    code: &'a str,
}

#[derive(Serialize, Deserialize)]
struct AuthenticationData {
    sub: String,
    name: String,
    email: String,
    picture: String,
    token: Option<String>,
}

#[post("/authentication", data = "<auth_data>")]
async fn authenticate(
    auth_data: Json<GoogleAuthData<'_>>,
) -> Result<Json<AuthenticationData>, Custom<&'static str>> {
    let url = "https://www.googleapis.com/oauth2/v3/userinfo";

    let res = reqwest::get(format!("{}?access_token={}", url, auth_data.code))
        .await
        .map_err(|_| Custom(Status::ServiceUnavailable, "Failed to validate google code"))?;

    let mut data: AuthenticationData = res
        .json()
        .await
        .map_err(|_| Custom(Status::ServiceUnavailable, "Failed to validate google code"))?;

    let secret = std::env::var("SECRET").expect("SECRET to be set");

    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_bytes()).map_err(|_| {
        Custom(
            Status::InternalServerError,
            "Failed to generate credentials",
        )
    })?;

    let mut claims = BTreeMap::new();
    claims.insert("sub", &data.sub);

    let token = claims.sign_with_key(&key).map_err(|_| {
        Custom(
            Status::InternalServerError,
            "Failed to generate credentials",
        )
    })?;

    data.token = Some(token);

    Ok(Json(data))
}

#[launch]
fn rocket() -> _ {
    dotenv().ok();
    rocket::build().mount("/", routes![authenticate])
}
