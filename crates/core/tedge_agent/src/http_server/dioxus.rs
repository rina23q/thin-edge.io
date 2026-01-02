use axum::Router;
use dioxus::prelude::*;

use crate::dioxus_fullstack::views::Navbar;
use crate::dioxus_fullstack::views::Home;

#[cfg(feature = "server")]
pub fn dioxus_router() -> Router {
    let config = ServeConfig::builder();

    Router::new()
        .serve_dioxus_application(config, App)

}

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
pub enum Route {
    #[layout(Navbar)]
        #[route("/")]
        Home {},
}

const FAVICON: Asset = asset!("../dioxus_fullstack/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("../dioxus_fullstack/assets/styling/main.css");
const TAILWIND_CSS: Asset = asset!("../dioxus_fullstack/assets/tailwind.css");

#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }

        Router::<Route> {}
    }
}
// #[component]
// fn App() -> Element {
//     rsx! {
//         h1 { "tedge-agent Management Console" }
//         p { "Dioxus 0.7 integration is working!" }
//     }
// }
