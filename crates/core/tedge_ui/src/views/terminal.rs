use dioxus::prelude::*;

#[component]
pub fn Terminal() -> Element {
    rsx! {
        crate::components::RenderTerminal {}
    }
}
