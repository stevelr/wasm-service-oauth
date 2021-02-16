//! wasm-oauth plugin for wasm-service

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use service_logging::{
    log,
    Severity::{self, Verbose},
};
use std::fmt;
use wasm_service::{handler_return, Context, Handler, HandlerReturn, Request};

mod encoder;

use encoder::{decode, encode};

// size of AES encryption key (32 bytes=256 bits)
const AES_KEY_BYTES: usize = 32;

// aTTP Content-Type values
//const TEXT_PLAIN_UTF_8: &str = "text/plain; charset=UTF-8";
const TEXT_HTML: &str = "text/html";
const APPLICATION_JSON: &str = "application/json";

// Github api endpoint to get user profile
const GITHUB_GET_USER_API: &str = "https://api.github.com/user";

/// Maximum length of app url, not including "https://" prefix
/// There aren't any specific limitations in the code - this is just used for sanity checks
/// and can be safely increased if actual app urls are longer
const MAX_APP_URL_LEN: usize = 800;

/// Errors used in this crate
/// These aren't generally reported to http client, but are used internally for more descriptive logging
#[derive(Debug)]
pub enum Error {
    /// Configuration error
    Config(String),

    /// Encryption or description
    Encryption(String),

    /// Serialization or deserialization
    Serde {
        msg: &'static str,
        e: serde_json::Error,
    },

    /// GenericArray type failure (such as incorrect key length)
    ArrayLen,

    /// state or session expired
    TimeoutExpired,

    /// random generation failed (unlikely)
    Random(String),

    CookieDecode,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Send config errors to client (via http Response),
/// since they should help debugging during development, and aren't likely to occur in production
fn config_error_return(e: impl std::error::Error) -> HandlerReturn {
    HandlerReturn {
        status: 200,
        text: format!("Internal Error: {:?}", e),
    }
}

fn config_error(field: &str, msg: &str) -> Error {
    Error::Config(format!("field '{}': {}", field, msg))
}

fn config_field_empty(field: &str) -> Error {
    config_error(field, "must not be empty")
}

/// Test for valid syntax for github username (does not check whether the account
/// actually exists). This check is to prevent XSS attacks on error page.
/// Valid github username contains alphanumeric (US English) characters or single hyphens,
/// and cannot begin or end with a hyphen, and is no more than 39 characters in length.
pub fn is_valid_username_token(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 39
        || name.starts_with('-')
        || name.ends_with('-')
        || name.contains("--")
    {
        return false;
    }

    name.chars()
        .into_iter()
        .find(|c| !((*c).is_alphanumeric() || *c == '-'))
        .is_none()
}

/// Perform some checks on validity of return_url.
/// The primary purpose of this check is to avoid XSS attacks or other attacks where url is either
/// too long or contains invalid characters. We do not verify whether the domain and path of the url
/// are part of this app (that check would require additional configuration parameters,
/// which could be error-prone, and might not be that useful). Since this is only used
/// in the oauth flow, the performance overhead of url parsing should be negligible.
pub fn is_valid_return_url(return_url: &str) -> bool {
    if return_url.is_empty() || return_url.len() > MAX_APP_URL_LEN {
        return false;
    }
    let url = match reqwest::Url::parse(return_url) {
        Err(_) => return false,
        Ok(url) => url,
    };
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return false;
    };
    true
}

/// oauth token result (from POST /auth_token api)
#[derive(Deserialize)]
struct TokenData {
    access_token: String,
    token_type: String,
}

/// impl Display to avoid accidental logging of token
impl fmt::Display for TokenData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenData({}...)", &self.access_token[..4])
    }
}

/// Github user data (response from GET /user api)
#[derive(Debug, Deserialize)]
pub struct UserData {
    /// user login name
    pub login: String,

    /// github user id
    pub id: u64,

    /// Display name (optional - user may not have provided one)
    pub name: Option<String>,

    /// user email - only returned if oauth scope includes user:email
    pub email: Option<String>,
}

/// 'State' contains the return_url, where app will be redirected after authentication
#[derive(Debug, Serialize, Deserialize)]
struct State(String); // holds return_url

#[async_trait]
pub trait AuthCheck {
    /// Determine whether user is authorized for the url/action within the app.
    /// Returns OK if the user is authorized to perform the request,
    /// If not authorized, handler can either set ctx to redirect, or return an error page in HandlerReturn
    async fn check_authorized(
        &self,
        req: &Request,
        ctx: &mut Context,
        user: &UserData,
    ) -> Result<(), HandlerReturn>;
}

/// Session data contains the user login name (0) (github user) and access token (1)
#[derive(Debug, Serialize, Deserialize)]
pub struct Session(String, String);

/// Configuration for OAuthHandler plugin
pub struct OAuthConfig {
    /// Function to generate auth failed response - what appears when user lands on /login-failed.
    /// either as a redirect (status 302 + Location header), or html (status 200 + error notice)
    /// When used in conjunction with `auth_error_redirect`, `auth_error_redirect` returns a 302/303
    /// status and a Location header, and this function generates the actual error page.
    pub auth_failed_response: fn(&Request, ctx: &mut Context, return_url: &str),

    /// Handler for authorization checking based on current user and request
    pub auth_checker: Box<dyn AuthCheck>,

    /// Generate auth error, for any cause including failed login, invalid session, and
    /// attempts to hack protocol. To avoid disclosing too much about our internal checks
    /// to a hacker, the error message is not very descriptive. Logs contain more detailed info.
    /// The function should do one of the following:
    /// - use ctx to set a Location header and redirect (status 302 or 303)
    /// - return text of an error page, either in ctx.response().text() or in HandlerReturn::text.
    /// To guard against XSS attacks, any parameters used in the url that appear on
    /// the error page must be sanitized.
    pub auth_error_redirect: fn(ctx: &mut Context, url: Option<&str>) -> HandlerReturn,

    /// Default url for app. This url is used after authentication
    /// if "redirect_url" is not specified or could not be parsed.
    pub app_url: String,

    /// Default url to send users who failed authN.authZ
    /// Should not be the same as app_url if app_url requires auth
    pub logged_out_app_url: String,

    /// Url prefix of this app to begin authorization flow. Default: "/authorize"
    /// If the app determines that authentication/authorization is required, it may redirect
    /// the user to this url appended with "?redirect_url=...", and the user will be redirected
    /// to that app url after authentication has completed.
    pub authorize_url_path: String,

    /// url prefix for code url redirect from oauth provider.
    /// This must match the redirect url in configuration for the OAuth app (at github.com)
    pub code_url_path: String,

    /// Where to send user after failed authentication
    pub login_failed_url_path: String,

    /// URL to force logout: clear cookies and redirect to app main page
    pub logout_url_path: String,

    /// User-Agent header string to be sent to oauth provider. Default: "wasm-oauth vx,y,z",
    /// where x,y.z is the build version of the wasm-oauth crate
    pub user_agent: String,

    /// Allowed origins. default: `vec!["*"]`.
    pub cors_origins: Vec<String>,

    /// Comma-separated list of allowed methods. Default:  `"GET,POST,OPTIONS"`
    pub cors_allow_methods: String,

    /// Length of time, in seconds, browser may cache CORS results. Default: 1 day (24 * 3600)
    pub cors_allow_age_sec: u64,

    /// CORS allowed headers: comma-separated list of allowed headers.
    /// Default: "Content-Type,Origin,Accept,Accept-Language,X-Requested-With"
    pub cors_allow_headers: String,

    /// Oauth provider url for authorize. Default: "https://github.com/login/oauth/authorize"
    pub provider_authorize_url: String,

    /// Oauth provider url for retrieving token. Default: "https://github.com/login/oauth/access_token"
    pub provider_token_url: String,

    /// Oauth scopes: space-separated list of scopes. At minimum, must include "read:user".
    /// If user email address is required, add "user:email"
    pub oauth_scopes: String,

    /// Client id assigned by oauth provider. REQUIRED
    pub client_id: String,

    /// Client secret assigned by oauth provider. REQUIRED
    pub client_secret: String,

    /// Key used for encrypting state data. Must be 32 bytes. REQUIRED
    pub state_secret: Vec<u8>, // must be 32 bytes

    /// Timeout for state encryption during login flow. default 5 minutes
    pub state_timeout_sec: u64,

    /// Secret key used for encrypting session data. Must be 32 bytes. REQUIRED
    pub session_secret: Vec<u8>,

    /// Max age of session cookie, in seconds. Default 3 days (3 * 24 * 60 * 60).
    /// Upon expiration of session, user may need to re-verify github account and is re-checked
    /// against list of authorized users.
    pub session_timeout_sec: u64,

    /// Url path prefix for urls that will receive session cookie. Default: "/"
    pub session_cookie_path_prefix: String,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),            // MUST-CHANGE
            client_secret: String::new(),        // MUST-CHANGE
            state_secret: Vec::new(),            // MUST-CHANGE
            session_secret: Vec::new(),          // MUST-CHANGE
            app_url: String::new(),              // MUST-CHANGE
            logged_out_app_url: "/".to_string(), // REVIEW

            session_cookie_path_prefix: "/".to_string(), // REVIEW
            oauth_scopes: "read:user".to_string(),       // REVIEW

            auth_failed_response,
            auth_checker: Box::new(AlwaysDeny {}),
            auth_error_redirect,
            authorize_url_path: "/authorize".to_string(),
            code_url_path: "/authorized".to_string(),
            login_failed_url_path: "/login-failed".to_string(),
            logout_url_path: "/logout".to_string(),
            user_agent: "wasm-oauth".to_string(),
            cors_origins: vec!["*".to_string()],
            cors_allow_methods: "GET,POST,OPTIONS".to_string(),
            cors_allow_age_sec: 24 * 60 * 60, // 1 day, in seconds
            cors_allow_headers: "Content-Type,Origin,Accept,Accept-Language,X-Requested-With"
                .to_string(),
            provider_authorize_url: "https://github.com/login/oauth/authorize".to_string(),
            provider_token_url: "https://github.com/login/oauth/access_token".to_string(),
            session_timeout_sec: 3 * 24 * 60 * 60, // 3 days
            state_timeout_sec: 5 * 60,             // 5 minutes
        }
    }
}

/// Implementation of authorization check that permits all operations
pub struct AlwaysAllow {}

#[async_trait]
impl AuthCheck for AlwaysAllow {
    async fn check_authorized(
        &self,
        _req: &Request,
        _ctx: &mut Context,
        _user: &UserData,
    ) -> Result<(), HandlerReturn> {
        Ok(())
    }
}

/// Implementation of authorization check that denies all operations
pub struct AlwaysDeny {}

#[async_trait]
impl AuthCheck for AlwaysDeny {
    async fn check_authorized(
        &self,
        _req: &Request,
        _ctx: &mut Context,
        _user: &UserData,
    ) -> Result<(), HandlerReturn> {
        Err(handler_return(403, "Not Allowed"))
    }
}

/// Instance data for OAuthHandler
pub struct OAuthHandler {
    config: OAuthConfig,
}

/// Implementation of AuthCheck that allows users if they are in approved users list
#[derive(Debug)]
pub struct UserAllowList {
    /// List of users approved for all operations
    pub allowed_users: Vec<String>,
    /// Url that will be used for redirect when users fail login
    pub login_failed_url: String,
}

#[async_trait]
impl AuthCheck for UserAllowList {
    async fn check_authorized(
        &self,
        _req: &Request,
        mut ctx: &mut Context,
        user: &UserData,
    ) -> Result<(), HandlerReturn> {
        log!(ctx, Verbose, _:"gh_valid_name",name:&user.login);
        if self.allowed_users.iter().any(|u| u == &user.login) {
            // found match in authorized list, return Ok ("authorized")
            log!(ctx, Verbose, _:"user_allowed", user: &user.login);
            Ok(())
        } else {
            // github user is not in authorized list
            log!(ctx, Verbose, _:"user_allowed_not_found", user: &user.login);
            // error page 'user' param
            Err(auth_error_redirect(
                &mut ctx,
                Some(&format!("{}?user={}", self.login_failed_url, &user.login)),
            ))
        }
    }
}

/// Generate auth error (for any cause including attempts to hack protocol, use invalid sessions,
/// etc.) In these cases we don't want to give an error that is too descriptive.
/// The optional url may include parameters to customize the error page,
/// however, it is IMPORTANT that the URL, including all parameters, is sanitized to avoid XSS attacks,
/// in particular, query parameters should not be derived from user input.
fn auth_error_redirect(ctx: &mut Context, url: Option<&str>) -> HandlerReturn {
    let _ = ctx
        .response()
        .header("Location", url.unwrap_or("/login-failed"))
        .unwrap()
        .header(
            "Set-Cookie",
            "session=0; Path=/x; HttpOnly; Secure; SameSite=None; Max-Age=0",
        )
        .unwrap();
    handler_return(303, "")
}

/// Generate response for user-not-authorized (error page, redirect, etc)
/// Error page for user-not-authorized
/// If user parameter is provided, error clarifies that Github auth succeeded,
/// but that user is not authorized for this app.
fn auth_failed_response(req: &Request, ctx: &mut Context, return_url: &str) {
    let msg = if let Some(user) = req.get_query_value("user") {
        format!(
            r#"<p>Github user '{}' is not authorized to use this app.
            Contact this app's administrator if '{}' should be added to the authorized users list,
            or log out of <a href="https://github.com">Github</a> to try a different user</p>"#,
            user, user
        )
    } else {
        String::default()
    };
    let body = format!(
        r#"<html>
    <body><p>This app requires an authorized github user.</p>
    {}<p><a href="{}">Return to app</a></p>
    </body>
    </html>
    "#,
        msg, return_url
    );
    // Send status 200 with this page since it's a "landing" page
    // unwrap ok here because static ascii
    ctx.response()
        .status(200)
        .content_type(TEXT_HTML)
        .unwrap()
        .text(body);
}

impl OAuthHandler {
    /// Validate parameters and initialize oauth handler
    pub fn init(config: OAuthConfig) -> Result<Self, Error> {
        // try to catch user errors that are easy to catch and give feedback on how to fix
        if config.app_url.is_empty() {
            return Err(config_field_empty("app_url"));
        }
        if config.client_id.is_empty() {
            return Err(config_field_empty("client_id"));
        }
        if config.client_secret.is_empty() {
            return Err(config_field_empty("client_secret"));
        }
        if config.user_agent.is_empty() {
            return Err(config_field_empty("user_agent"));
        }
        if config.state_secret.len() != AES_KEY_BYTES {
            return Err(config_error("state_secret", "must be 32-byte secret key"));
        }
        if config.cors_origins.is_empty() {
            return Err(config_field_empty("cors_origins"));
        }
        if config.cors_allow_age_sec > 7 * 24 * 60 * 60 || config.cors_allow_age_sec < 10 * 60 {
            return Err(config_error(
                "cors_allow_age_sec",
                "should be from 10 minutes to 7 days - did you use a value in seconds?",
            ));
        }
        if config.state_timeout_sec > 10 * 60 || config.state_timeout_sec < 60 {
            return Err(config_error("state_timeout_sec", "should be from 1 minute to 10 minutes (Github times out after 10 min). Value is in seconds"));
        }
        if config.session_secret.len() != AES_KEY_BYTES {
            return Err(config_error("session_secret", "must be 32-byte secret key"));
        }
        if config.session_timeout_sec > 31 * 24 * 60 * 60 || config.session_timeout_sec < 10 * 60 {
            return Err(config_error(
                "session_timeout_sec",
                "Session timeout should be from 10 minutes to 31 days. Value is in seconds",
            ));
        }
        if config.cors_allow_methods.find("GET").is_none()
            || config.cors_allow_methods.find("OPTIONS").is_none()
        {
            return Err(config_error("cors_allow_methods", "must include at least GET and OPTIONS. Value should be a comma-separated list of options, such as \"GET,POST,OPTIONS\""));
        }
        if config.oauth_scopes.find("read:user").is_none() {
            return Err(config_error(
                "oauth_scopes",
                "must include at least read:user. Values should be a space-separated list",
            ));
        }
        Ok(OAuthHandler { config })
    }

    /// Append CORS headers to response
    pub fn add_cors_headers(
        &self,
        req: &Request,
        ctx: &mut Context,
    ) -> Result<(), wasm_service::Error> {
        let allow_origin = self.map_cors_origin(req.get_header("origin"));
        ctx.response()
            .header("Access-Control-Allow-Origin", allow_origin)?
            .header(
                "Access-Control-Allow-Methods",
                &self.config.cors_allow_methods,
            )?
            .header(
                "Access-Control-Max-Age",
                self.config.cors_allow_age_sec.to_string(),
            )?
            .header(
                "Access-Control-Allow-Headers",
                "Content-Type,Origin,Accept,Accept-Language,X-Requested-With",
            )?;
        Ok(())
    }

    /// If requested origin is in list, return it (allow it); otherwise, return first origin in allowed list
    /// For credentialed request, return value should never be wildcard "*"
    pub fn map_cors_origin(&self, origin: Option<String>) -> &str {
        if let Some(origin) = origin {
            if let Some((i, _)) = self
                .config
                .cors_origins
                .iter()
                .enumerate()
                .find(|(_, path)| *path == origin.as_str())
            {
                return &self.config.cors_origins[i];
            }
        }
        &self.config.cors_origins[0]
    }

    /// Use code passed to /authorize to fetch auth token using POST
    /// Any errors encountered (including bug or http err) will cause redirect to Unauthorized page
    async fn get_github_token(
        &self,
        mut ctx: &mut Context,
        code: &str,
        state: &str,
    ) -> Result<String, HandlerReturn> {
        log!(ctx, Verbose, _:"get_token", code: code);
        match self
            .parse_json_response::<TokenData>(
                "get_token",
                reqwest::Client::new()
                    .post(&self.config.provider_token_url)
                    .form(&[
                        ("client_id", &self.config.client_id),
                        ("client_secret", &self.config.client_secret),
                        ("code", &code.to_string()),
                        ("state", &state.to_string()),
                    ])
                    .header("Accept", APPLICATION_JSON)
                    .header("Cache-Control", "no-store, max-age=0")
                    .header("User-Agent", &self.config.user_agent)
                    .send()
                    .await,
            )
            .await
        {
            Ok(token_data) if token_data.token_type == "bearer" => Ok(token_data.access_token),
            Ok(token_data) => {
                log!(ctx, Severity::Error, _:"get_token type-err",
                         expect:"bearer", actual:&token_data.token_type);
                Err((self.config.auth_error_redirect)(&mut ctx, None))
            }
            Err(msg) => {
                log!(ctx, Severity::Error, text: msg);
                Err((self.config.auth_error_redirect)(&mut ctx, None))
            }
        }
    }

    /// Using user's auth token, query github.com for user profile info using "GET /user"
    /// Any errors encountered will result in Unauthorized error to user
    /// (even if error is due to bug or http failure)
    async fn get_github_user(
        &self,
        mut ctx: &mut Context,
        oauth_token: &str,
    ) -> Result<UserData, HandlerReturn> {
        log!(ctx, Verbose, _:"get_github_user", token: &oauth_token[..8]);

        match self
            .parse_json_response(
                "get_user",
                reqwest::Client::new()
                    .get(GITHUB_GET_USER_API)
                    .header("Authorization", format!("token {}", oauth_token))
                    .header("Accept", APPLICATION_JSON)
                    .header("Cache-Control", "no-store, max-age=0")
                    .header("User-Agent", &self.config.user_agent)
                    .send()
                    .await,
            )
            .await
        {
            Ok(user) => Ok(user),
            Err(msg) => {
                log!(ctx, Severity::Error, text: msg);
                Err((self.config.auth_error_redirect)(&mut ctx, None))
            }
        }
    }

    /// Parse result into json object.
    async fn parse_json_response<T: DeserializeOwned>(
        &self,
        query: &str,
        response: Result<reqwest::Response, reqwest::Error>,
    ) -> Result<T, String> {
        let response = response
            .map_err(|e| format!("gh_query http-err, q={} error={}", query, e.to_string()))?;
        if !response.status().is_success() {
            return Err(format!(
                "gh_query status-err, q={} status={}",
                query,
                response.status()
            ));
        }
        let headers = dump_headers(&response);
        let text = response
            .text()
            .await
            .map_err(|e| format!("gh_query body-err, q={} error={}", query, e.to_string()))?;
        let obj = serde_json::from_str::<T>(&text).map_err(|e| {
            format!(
                "gh_query json-err, q={} body={}, error={}, headers={}",
                query,
                &text,
                e.to_string(),
                headers
            )
        })?;
        Ok(obj)
    }

    /// OAUTH step 1: redirect user's browser to login url of oauth provider
    /// Provider verifies credentials, then redirects browser to /authorized.
    /// return_url is what we want our app to return to after authentication is complete.
    /// "state" is encrypted form of return_url and contains a random nonce,
    /// so it's unique to each user/request.
    /// "scope" contains the oauth scopes we are requesting, which for now is just the user
    /// profile, so we can get the login id
    fn handle_oauth_login<'req>(
        &self,
        req: &'req Request,
        mut ctx: &mut Context,
    ) -> Result<(), HandlerReturn> {
        let return_url = req
            .get_query_value("return_url")
            .map(|s| s.to_string())
            // if someone attempts to force an invalid return_url, rewrite it to default app url
            .filter(|u| is_valid_return_url(u))
            // also, missing return_url is replaced with app default url
            .unwrap_or_else(|| self.config.app_url.to_string());
        let location = match encode(
            State(return_url),
            &self.config.state_secret,
            self.config.state_timeout_sec as u64,
        ) {
            Ok(state) => Some(format!(
                "{}?client_id={}&state={}&scope={}",
                self.config.provider_authorize_url,
                self.config.client_id,
                state,
                self.config.oauth_scopes,
            )),
            Err(e) => {
                log!(ctx, Severity::Error, _:"oa1.encode", error:e);
                None
            }
        };
        match location {
            Some(location) => {
                log!(ctx, Verbose, _:"oa1", location: location);
                // unwrap ok because location string is all ascii
                ctx.response()
                    .status(302)
                    .header("Location", location)
                    .unwrap();
                Ok(())
            }
            None => Err((self.config.auth_error_redirect)(&mut ctx, None)),
        }
    }

    /// OAUTH step 2: provider verified credentials and redirected the user here,
    /// passing the "state" we created in step 1, and a code we can use to get a token
    /// representing the authenticated user.
    /// any errors recovering state (including missing query parameters,
    /// invalid/corrupted state, or expired timeouts due to replay attacks) will fail
    async fn handle_oauth_response(
        &self,
        req: &Request,
        mut ctx: &mut Context,
    ) -> Result<(), HandlerReturn> {
        let state = req.get_query_value("state").ok_or_else(|| {
            log!(ctx, Severity::Error, _:"oa2:missing_state");
            (self.config.auth_error_redirect)(&mut ctx, None)
        })?;
        let decoded_state: State =
            decode(state.as_ref(), &self.config.state_secret).map_err(|e| {
                log!(ctx, Severity::Error, _:"oa2:decode", error: e);
                (self.config.auth_error_redirect)(&mut ctx, None)
            })?;
        let return_url = decoded_state.0;

        // use the 'code' provided by github to request access token
        // We must pass in 'state' with the same value used in step 1.
        let code = req.get_query_value("code").ok_or_else(|| {
            log!(ctx, Severity::Error, _:"oa2:missing_code");
            (self.config.auth_error_redirect)(&mut ctx, None)
        })?;
        let token = self
            .get_github_token(&mut ctx, code.as_ref(), state.as_ref())
            .await?;

        // Use the token to get the user's id, and verify the user is approved to use the app.
        let user = self.get_github_user(&mut ctx, &token).await?;
        if is_valid_username_token(&user.login) {
            self.config
                .auth_checker
                .check_authorized(req, &mut ctx, &user)
                .await?;
        } else {
            log!(ctx, Severity::Error, msg:"Invalid chars in github username",name:&user.login);
            return Err(auth_error_redirect(
                &mut ctx,
                Some(&self.config.login_failed_url_path),
            ));
        }
        // Create session with approved user and user's token
        let session_cookie = encode(
            Session(user.login.clone(), token.clone()),
            &self.config.session_secret,
            self.config.session_timeout_sec as u64,
        )
        .map_err(|e| {
            log!(ctx, Severity::Error, _:"oa2:encode_session", error: e);
            (self.config.auth_error_redirect)(&mut ctx, None)
        })?;
        log!(ctx, Verbose, _:"oa2:set-session", cookie: session_cookie,
            user: &user.login, token: &token[..8], return_url: &return_url);

        // Authentication + Authorization complete!
        // Set session cookie and Redirect to the application.
        ctx.response()
            .status(302)
            .header("Location", &return_url)
            .unwrap() // unwrap ok: return_url already validated
            .header(
                "Set-Cookie",
                format!(
                    "session={}; Path={}; HttpOnly; Secure; SameSite=None; Max-Age={}",
                    session_cookie,
                    self.config.session_cookie_path_prefix,
                    self.config.session_timeout_sec
                ),
            )
            .unwrap(); // all ascii
        Ok(())
    }

    /// Send user back through the oauth workflow. This may occur if user tries to hit
    /// url that requires authentication, and session cookie is either missing or expired.
    /// redirect_url should be the app url to returning to after auth has completed.
    pub fn re_authorize(&self, ctx: &mut Context, redirect_url: &str) -> HandlerReturn {
        // Returns Error::Response with redirect. other error conditions here only occur if header
        // value has non-ascii chars
        log!(ctx, Verbose, _:"re_authorize", redirect_url: redirect_url);
        ctx.response()
            .header(
                "Location",
                format!(
                    "{}?redirect_url={}",
                    self.config.authorize_url_path, redirect_url
                ),
            )
            .unwrap() // unwrap ok because redirect_url already verified
            .header(
                // Max-Age expires the cookie immediately
                "Set-Cookie",
                "session=0; Path=/x; HttpOnly; Secure; SameSite=None; Max-Age=0",
            )
            .unwrap(); // unwrap ok all ascii
        handler_return(303, "")
    }

    /// Verify that user is authenticated and authorized. Call this at the front
    /// of every handler that requires authN+authZ. Any failure results in 400
    pub fn verify_auth_user(
        &self,
        req: &Request,
        mut ctx: &mut Context,
    ) -> Result<Session, HandlerReturn> {
        use wasm_service::Method;
        let redirect_url = if req.method() == Method::GET {
            req.url().to_string()
        } else {
            self.config.app_url.to_string()
        };
        let sess_cookie = req
            .get_cookie_value("session")
            .ok_or_else(|| self.re_authorize(&mut ctx, &redirect_url))?;
        let session: Session = match decode(&sess_cookie, &self.config.session_secret) {
            Ok(session) => session,
            Err(Error::TimeoutExpired) => {
                let url = req.url();
                // Redirect to get authorization again
                let redirect_url = if req.method() == Method::GET {
                    url.to_string()
                } else {
                    self.config.app_url.to_string()
                };
                log!(ctx, Verbose,_:"verify_auth timeout", redirect_url:redirect_url);
                return Err(self.re_authorize(&mut ctx, &redirect_url));
            }
            Err(e) => {
                log!(ctx, Severity::Error, _:"session-decode error", error: e);
                return Err((self.config.auth_error_redirect)(&mut ctx, None));
            }
        };
        log!(ctx, Verbose, _:"verify_auth success", user: &session.0);
        // user is authenticated and session is valid
        self.add_cors_headers(req, &mut ctx)
            .map_err(config_error_return)?;
        Ok(session)
    }

    /// Log out the user by deleting cookies.
    /// Redirect the user to url, or to app base url if url is None
    fn logout(
        &self,
        _req: &Request,
        ctx: &mut Context,
        url: Option<&str>,
    ) -> Result<(), HandlerReturn> {
        let _ = ctx
            .response()
            .header("Location", url.unwrap_or(&self.config.logged_out_app_url))
            .unwrap()
            .header(
                "Set-Cookie",
                "session=0; Path=/0; HttpOnly; Secure; SameSite=None; Max-Age=0",
            )
            .unwrap();
        Err(handler_return(303, ""))
    }

    /// Returns true if this handler would process the url, i.e., if the request url
    /// matches one of the configured url prefixes.
    pub fn would_handle(&self, req: &Request) -> bool {
        let path = req.url().path();
        let conf = &self.config;
        let auth_prefixes = vec![
            &conf.authorize_url_path,
            &conf.code_url_path,
            &conf.login_failed_url_path,
            &conf.logout_url_path,
        ];
        req.method() == wasm_service::Method::OPTIONS
            || (req.method() == wasm_service::Method::GET
                && auth_prefixes.iter().any(|&prefix| path.starts_with(prefix)))
    }
}

fn dump_headers(resp: &reqwest::Response) -> String {
    resp.headers()
        .into_iter()
        .map(|(k, v)| format!("({}:{})", k, v.to_str().unwrap_or("")))
        .collect::<Vec<String>>()
        .join("\n")
}

#[async_trait(? Send)]
impl Handler for OAuthHandler {
    /// Process incoming Request
    async fn handle(&self, req: &Request, mut ctx: &mut Context) -> Result<(), HandlerReturn> {
        use wasm_service::Method::{GET, OPTIONS};

        match (req.method(), req.url().path()) {
            (OPTIONS, _) => {
                self.add_cors_headers(req, &mut ctx)
                    .map_err(config_error_return)?;
                ctx.response().status(204);
            }
            (GET, authorize_url) if authorize_url == self.config.authorize_url_path => {
                self.handle_oauth_login(req, &mut ctx)?;
            }
            (GET, code_url) if code_url == self.config.code_url_path => {
                log!(ctx, Verbose, _:"authorized", url:req.url());
                self.handle_oauth_response(req, &mut ctx).await?;
            }
            (GET, failed_url) if failed_url == self.config.login_failed_url_path => {
                (self.config.auth_failed_response)(req, &mut ctx, &self.config.app_url);
            }
            (GET, logout_url) if logout_url == self.config.logout_url_path => {
                // clear cookies and redirect to app base url
                self.logout(req, &mut ctx, None)?;
            }
            _ => { /* fall through */ }
        }
        Ok(())
    }
}

/// InitHandler: Log all requests and set security headers
struct InitHandler {}

#[async_trait(? Send)]
impl Handler for InitHandler {
    async fn handle(&self, req: &Request, ctx: &mut Context) -> Result<(), HandlerReturn> {
        // log all incoming http hits
        log!(ctx, Verbose, _:"handler", method: req.method(), url: req.url());
        // tighten security with response headers
        ctx.response()
            // prevent showing pages in iframes
            .header("X-Frame-Options", "DENY")
            .unwrap() // unwrap ok because using static ascii
            // no cross-origin deps on scripts or css
            //.header("Content-Security-Policy", "default-src 'self'")?
            // don't cache responses
            .header(
                "Cache-Control",
                "no-store, no-cache, must-revalidate, proxy-revalidate",
            )
            .unwrap(); // unwrap ok because using static ascii

        Ok(())
    }
}

#[test]
fn test_gh_username() {
    assert!(is_valid_username_token("alice"));
    assert!(is_valid_username_token("mid-hyphen"));

    assert!(!is_valid_username_token(""));
    assert!(!is_valid_username_token(
        "1234567890123456789012345678901234567890"
    )); // 40 chars
    assert!(!is_valid_username_token("joe$"));
    assert!(!is_valid_username_token("bob%"));
    assert!(!is_valid_username_token("s p a c e"));
    assert!(!is_valid_username_token("hyphen--s"));
    assert!(!is_valid_username_token("-start0hyphen"));
    assert!(!is_valid_username_token("end-hyphen-"));
    assert!(!is_valid_username_token("nonascii▲"));
}

#[test]
fn test_return_url() {
    assert!(is_valid_return_url("https://api.example.com"));
    assert!(is_valid_return_url(
        "https://api.example.com/path/_x-y.html?this=that&other=this"
    ));
}
