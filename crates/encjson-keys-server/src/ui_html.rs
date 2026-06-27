use std::fmt::Write as _;

use axum::http::HeaderMap;

pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(crate) fn layout(title: &str, tabs: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{}</title>
  <link href="https://unpkg.com/@tabler/core@latest/dist/css/tabler.min.css" rel="stylesheet">
  <script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body class="bg-light">
  <div class="page">
    <header class="navbar navbar-expand-md navbar-light d-print-none">
      <div class="container-xl">
        <span class="navbar-brand">encjson-keys-server</span>
        <div class="navbar-nav ms-auto">
          <a class="nav-link" href="/ui/logout">Logout</a>
        </div>
      </div>
    </header>
    <div class="page-wrapper">
      <div class="container-xl mt-3">
        {}
        <div class="card mt-3">
          <div class="card-body">
            {}
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>"#,
        title, tabs, body
    )
}

pub(crate) fn tabs(active: &str) -> String {
    let items = [
        ("keys", "Keys", "/ui/keys"),
        ("requests", "Requests", "/ui/requests"),
        ("tenants", "Tenants", "/ui/tenants"),
    ];
    let mut out = String::new();
    out.push_str(r#"<ul class="nav nav-tabs">"#);
    for (id, label, href) in items {
        let cls = if id == active {
            "nav-link active"
        } else {
            "nav-link"
        };
        let _ = write!(
            out,
            r#"<li class="nav-item"><a class="{}" href="{}">{}</a></li>"#,
            cls, href, label
        );
    }
    out.push_str("</ul>");
    out
}

pub(crate) fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let mut it = part.trim().splitn(2, '=');
        let k = it.next()?.trim();
        let v = it.next()?.trim();
        if k == name {
            return Some(v.to_string());
        }
    }
    None
}

pub(crate) fn set_cookie(value: &str, secure: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let mut cookie = format!("encjson_ui={value}; HttpOnly; SameSite=Lax; Path=/");
    if secure {
        cookie.push_str("; Secure");
    }
    headers.insert(axum::http::header::SET_COOKIE, cookie.parse().unwrap());
    headers
}
