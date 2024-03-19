use std::{
    convert::Infallible,
    time::{Duration, SystemTime},
};

use dotenv::dotenv;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rocket::{
    http::{HeaderMap, Status},
    request::{FromRequest, Outcome},
    response::status::Custom,
    serde::json::Json,
    Request,
};
use serde::{Deserialize, Serialize};

#[macro_use]
extern crate rocket;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    aud: String,
    exp: u64,
}

#[derive(Deserialize)]
struct GoogleAuthData<'a> {
    code: &'a str,
}

#[derive(Serialize)]
struct RefreshData {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct AuthenticationData {
    sub: String,
    name: String,
    email: String,
    picture: String,
    token: Option<String>,
}

struct RequestHeaders<'h>(&'h HeaderMap<'h>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequestHeaders<'r> {
    type Error = Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let request_headers = request.headers();
        Outcome::Success(RequestHeaders(request_headers))
    }
}

#[post("/authentication", data = "<auth_data>")]
async fn authenticate(
    auth_data: Json<GoogleAuthData<'_>>,
) -> Result<Json<AuthenticationData>, Custom<&str>> {
    let url = "https://www.googleapis.com/oauth2/v3/userinfo";

    let res = reqwest::get(format!("{}?access_token={}", url, auth_data.code))
        .await
        .map_err(|_| Custom(Status::ServiceUnavailable, "Failed to validate google code"))?;

    let mut data: AuthenticationData = res
        .json()
        .await
        .map_err(|_| Custom(Status::ServiceUnavailable, "Failed to validate google code"))?;

    let secret = std::env::var("SECRET").expect("SECRET to be set");
    let app_id = std::env::var("APP_ID").expect("APP_ID to be set");
    let exp = SystemTime::now()
        .checked_add(Duration::new(3600, 0))
        .expect("Time to be valid")
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| {
            Custom(
                Status::InternalServerError,
                "Failed to generate credentials",
            )
        })?
        .as_secs();

    let claims = Claims {
        aud: app_id,
        sub: data.sub.to_owned(),
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|_| {
        Custom(
            Status::InternalServerError,
            "Failed to generate credentials",
        )
    })?;

    data.token = Some(token);

    Ok(Json(data))
}

#[get("/refresh")]
fn refresh(headers: RequestHeaders) -> Result<Json<RefreshData>, Custom<&str>> {
    let secret = std::env::var("SECRET").expect("SECRET to be set");
    let token = headers
        .0
        .get_one("authorization")
        .ok_or(Custom(Status::Unauthorized, "Invalid credentials"))?
        .replace("Bearer ", "");

    let mut validator = Validation::default();
    validator.validate_exp = false;
    validator.validate_aud = false;

    let data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validator,
    )
    .map_err(|_| Custom(Status::Unauthorized, "Invalid credentials"))?;

    let exp = SystemTime::now()
        .checked_add(Duration::new(3600, 0))
        .expect("Time to be valid")
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| {
            Custom(
                Status::InternalServerError,
                "Failed to generate credentials",
            )
        })?
        .as_secs();

    let claims = Claims {
        aud: data.claims.aud,
        sub: data.claims.sub,
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|_| {
        Custom(
            Status::InternalServerError,
            "Failed to generate credentials",
        )
    })?;

    Ok(Json(RefreshData { token }))
}

#[launch]
fn rocket() -> _ {
    dotenv().ok();
    rocket::build().mount("/", routes![authenticate, refresh])
}
