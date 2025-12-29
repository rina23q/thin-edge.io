use dioxus::prelude::*;
use std::collections::BTreeMap;
use std::collections::HashSet;

const CONFIG_CSS: Asset = asset!("/assets/styling/configurations.css");

// Define an enum to handle different filtering modes for better scalability
#[derive(Copy, Clone, PartialEq, Eq)]
enum ValueFilterMode {
    ShowAll,
    HideEmpty,
}

#[component]
pub fn Configurations() -> Element {
    // Fetch configuration list from the server-side tedge command
    let config_resource = use_resource(get_tedge_config_list);

    // UI states for accordion, search, and filtering
    let mut opened_sections = use_signal(HashSet::<String>::new);
    let mut search_query = use_signal(String::new);
    let mut filter_mode = use_signal(|| ValueFilterMode::ShowAll);

    // Resource state handling
    let resource = config_resource.read();
    let Some(result) = resource.as_ref() else {
        return rsx! { div { class: "loading-spinner", "Loading configurations..." } };
    };

    let map = match result {
        Ok(m) => m,
        Err(e) => return rsx! { div { class: "error-message", "Error: {e}" } },
    };

    // Filter and group configurations based on current UI state
    let mut grouped_configs: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let query = search_query.read().to_lowercase();
    let current_filter = *filter_mode.read();

    for (full_key, value) in map {
        let matches_query =
            full_key.to_lowercase().contains(&query) || value.to_lowercase().contains(&query);

        let is_visible = match current_filter {
            ValueFilterMode::ShowAll => true,
            ValueFilterMode::HideEmpty => !value.trim().is_empty(),
        };

        if matches_query && is_visible {
            let prefix = full_key.split('.').next().unwrap_or("other").to_string();
            grouped_configs
                .entry(prefix)
                .or_default()
                .push((full_key.clone(), value.clone()));
        }
    }

    rsx! {
        document::Link { rel: "stylesheet", href: CONFIG_CSS }

        div { class: "config-dashboard",
            h1 {
                span { class: "title-brand", "thin-edge.io" }
                "Configuration"
            }

            // Unified toolbar for search and filtering
            div { class: "toolbar",
                div { class: "search-box",
                    span { class: "search-icon", "🔍" }
                    input {
                        class: "search-input",
                        placeholder: "Search keys or values...",
                        value: "{search_query}",
                        oninput: move |evt| search_query.set(evt.value())
                    }
                }

                div { class: "filter-box",
                    label { class: "filter-label", "Filter:" }
                    select {
                        class: "filter-select",
                        onchange: move |evt| {
                            match evt.value().as_str() {
                                "non-empty" => filter_mode.set(ValueFilterMode::HideEmpty),
                                _ => filter_mode.set(ValueFilterMode::ShowAll),
                            }
                        },
                        option { value: "all", "All Items" }
                        option { value: "non-empty", "Non-empty only" }
                    }
                }
            }

            for (prefix, items) in grouped_configs {
                {
                    let is_open = opened_sections.read().contains(&prefix);
                    let prefix_clone = prefix.clone();

                    rsx! {
                        section { class: "config-section", key: "{prefix}",
                            div {
                                class: "section-header clickable",
                                onclick: move |_| {
                                    let mut opened = opened_sections.write();
                                    if opened.contains(&prefix_clone) {
                                        opened.remove(&prefix_clone);
                                    } else {
                                        opened.insert(prefix_clone.clone());
                                    }
                                },
                                span { class: "icon", if is_open { "📂" } else { "📁" } }
                                span { class: "prefix-title", "{prefix}" }
                                span { class: "item-count", "{items.len()}" }
                                span { class: "spacer" }
                                span { class: "arrow", if is_open { "⏶" } else { "⏷" } }
                            }

                            if is_open {
                                div { class: "config-table animate-fade-in",
                                    for (key, value) in items {
                                        {
                                            rsx! {
                                                div { class: "config-row", key: "{key}",
                                                    div { class: "cell-key", "{key}" }
                                                    div { class: "cell-value-container",
                                                        span { class: "value-text", "{value}" }
                                                        button {
                                                            class: "copy-btn",
                                                            title: "Copy to clipboard",
                                                            onclick: move |_| {
                                                                // Escape backslashes and double quotes to prevent breaking the JS string literal.
                                                                // This is crucial for values like 'az.topics' which contain JSON-like arrays.
                                                                let escaped_value = value
                                                                    .replace('\\', "\\\\")
                                                                    .replace('"', "\\\"");

                                                                // Clipboard copy with "Copied!" feedback via JS
                                                                let js_code = format!(
                                                                    r##"
                                                                    const textToCopy = "{}";
                                                                    navigator.clipboard.writeText(textToCopy);
                                                                    
                                                                    const btn = event.target;
                                                                    const originalText = btn.innerText;
                                                                    btn.innerText = "Copied!";
                                                                    btn.style.color = "#10b981";
                                                                    
                                                                    setTimeout(() => {{
                                                                        btn.innerText = originalText;
                                                                        btn.style.color = "";
                                                                    }}, 2000);
                                                                    "##,
                                                                    escaped_value
                                                                );
                                                                document::eval(&js_code);
                                                            },
                                                            "📋"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[server]
pub async fn get_tedge_config_list() -> Result<BTreeMap<String, String>, ServerFnError> {
    let output = tokio::process::Command::new("tedge")
        .args(["config", "list", "--all"])
        .output()
        .await
        .map_err(|e| {
            ServerFnError::new(&format!(
                "Failed to execute 'tedge config list --all': {}",
                e
            ))
        })?;

    let mut config_map = BTreeMap::new();

    if !output.status.success() {
        eprintln!("Command failed with status: {}", output.status);
    } else {
        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| ServerFnError::new(&format!("Output contains invalid UTF-8: {}", e)))?;

        for line in stdout.lines() {
            if let Some((key, value)) = line.split_once('=') {
                config_map.insert(key.to_string(), value.to_string());
            }
        }
    }

    Ok(config_map)
}
