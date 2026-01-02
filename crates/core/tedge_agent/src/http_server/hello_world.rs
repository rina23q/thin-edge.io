use axum::{Router, response::Html, routing};

pub(crate) fn ui_router() -> Router {
    Router::new()
        .route("/ui", routing::get(index_handler))
}

async fn index_handler() -> Html<&'static str> {
    Html(r#"
        <!DOCTYPE html>
        <html>
            <head>
                <title>tedge-agent</title>
                <style>
                    body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f0f2f5; }
                    .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                    h1 { color: #2d3748; }
                </style>
            </head>
            <body>
                <div class="card">
                    <h1>tedge-agent is running</h1>
                    <p>Local Management UI (Draft)</p>
                </div>
            </body>
        </html>
    "#)
}
