use dioxus::prelude::*;

const HEADER_SVG: Asset = asset!("/assets/thin-edge-logo-dark.svg");

#[component]
pub fn Hero() -> Element {
    rsx! {
        // We can create elements inside the rsx macro with the element name followed by a block of attributes and children.
        div {
            // Attributes should be defined in the element before any children
            id: "hero",
            // After all attributes are defined, we can define child elements and components
            img { src: HEADER_SVG, id: "header" }
            div { id: "links",
                h1 { "Settings" }
                a { href: "/configurations", "⚙️ Configure thin-edge.io" }
                a { href: "/terminal", " ❯ Web Terminal" }
                h1 { "External Links" }
                a { href: "https://thin-edge.io/", "🚀 thin-edge.io" }
                a { href: "https://thin-edge.github.io/thin-edge.io/", "📚 Learn thin-edge.io" }
                a { href: "https://github.com/thin-edge/thin-edge.io/issues",
                    "🎫 Raise an issue on GitHub"
                }
                a { href: "https://discord.com/invite/sVX3B8nj5d", "👋 Discord Community" }
            }
        }
    }
}
