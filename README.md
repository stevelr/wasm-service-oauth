# wasm-service-oauth

Use OAuth with Cloudflare Workers

Examples below have been tested with Github. It should work with other oauth providers with minor changes.


## Setup

The configuration parameters are passed in an `OAuthConfig` struct to initialize the service.
The example below sets the secret parameters in the environment, so they aren't part of the compiled wasm binary.

1. Create an environment variable `env_json` containing json data, which will be parsed
   by the worker.
   
At the bottom of wrangler.toml, add the following.

```toml
[vars]

env_json= """{
  "oauth": {
    "app_url": "https://app.example.com/",
    "authorized_users": [ "gituser" ],
    "client_id" : "0000",
    "client_secret": "0000",
    "state_secret": "0000",
    "cors_origins": [ "https://app.example.com", "http://localhost:3000" ],
    "logged_out_app_url": "https://app.example.com/",
    "session_path_prefix": "/private/",
    "session_secret": "0000"
  }
}
```

- `app_url` : base url for your app
- `client_id`, `client_secret`: github api id and secret
- `state_secret`, `session_secret`: 32-bit encryption keys
  as 64 hex digits. One way to create these on unix: 
  
  ```head --bytes 32 /dev/urandom | hexdump -ve '1/1 "%.2x"' && echo```
  
- `logged_out_app_url`: where user will be redirected after logout
- `session_path_prefix`: any url beginning with this will have its session cookie set

2. Update your service program as follows

```rust2018
#[wasm_bindgen]
extern "C" {
    static env_json: String;
}

pub async fn main_entry(req: Jsvalue) -> Result<Jsvalue,JsValue> { 
    //  ...
    let environ_config = env_json.as_str();
    let settings = load(environ_config).map_err(|e| JsValue::from_str(&e))?;
    // ...

    let oauth_config = build_oauth_config(&settings.oauth)?;
    let oauth_handler = OAuthHandler::init(oauth_config)
        .map_err(|e| JsValue::from(&format!("OAuthHandler init error: {}", e.to_string())))?;
    
    
    wasm_service::service_request(
        req,
        ServiceConfig {
            logger, 
            handlers: vec![
                Box::new(MyHandler(oauth_handler))
            ],
            ..Default::default()
        }
    ).await
}

fn build_oauth_config(env: &Oauth) -> Result<OAuthConfig, JsValue> {
    let allow = wasm_service_oauth::UserAllowList {
        allowed_users: env.authorized_users.clone(),
        login_failed_url: "/login-failed".into(),
    };

    let config = OAuthConfig {
        app_url: env.app_url.to_string(),
        logged_out_app_url: env.logged_out_app_url.to_string(),
        authorize_url_path: "/authorize".to_string(),
        code_url_path: "/code".to_string(),
        login_failed_url_path: "/login-failed".to_string(),
        logout_url_path: "/logout".to_string(),
        auth_checker: Box::new(allow),
        client_id: env.client_id.to_string(),
        client_secret: env.client_secret.to_string(),
        state_secret: key_from_hex(&env.state_secret, 32).map_err(JsValue::from)?,
        session_secret: key_from_hex(&env.session_secret, 32).map_err(JsValue::from)?,
        session_cookie_path_prefix: env.session_path_prefix.to_string(),
        cors_origins: env.cors_origins.clone(), // .iter().map(|v| v.as_ref()).collect(),
        ..Default::default()
    };
    Ok(config)
}

/// load config from environment
pub(crate) fn load(json: &str) -> Result<Config, String> {
    //let var = std::env::var("env_json")
    //    .map_err(|_| Error::Environment("Missing env_json".to_string()))?;
    let conf = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(conf)
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub oauth: Oauth,
}
#[derive(Debug, Deserialize)]
pub struct Oauth {
    pub client_id: String,
    pub client_secret: String,
    pub state_secret: String,
    pub session_secret: String,
    pub session_path_prefix: String,
    pub app_url: String,
    pub logged_out_app_url: String,
    pub cors_origins: Vec<String>,
    pub authorized_users: Vec<String>,
}
```

3. Update the handler function as follows
```rust2018
async fn handle(&self, req: &Request, mut ctx: &mut Context) -> Result<(), HandlerReturn> {
    
    // urls beginning with session_path_prefix require authentication
    if req.url().path().starts_with("/private/") {
        let _session = self.oauth_handler.verify_auth_user(req, &mut ctx)?;
        // user is authenticated!!
        // ...

    } else {
        // handle urls not requiring authentication
        // ...
    }

    // let oauth handler process its urls
    if ctx.response().is_unset() {
        if self.oauth_handler.would_handle(&req) {
            // handle oauth processing for /code, /authorize, /login-failed, etc.
            self.oauth_handler.handle(req, &mut ctx).await?;
        }
    }
    Ok(())
}
```