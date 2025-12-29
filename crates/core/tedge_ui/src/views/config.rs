use dioxus::prelude::*;
use std::collections::BTreeMap;
use std::collections::HashSet;

const CONFIG_CSS: Asset = asset!("/assets/styling/config.css");

// Define an enum to handle different filtering modes for better scalability
#[derive(Copy, Clone, PartialEq, Eq)]
enum ValueFilterMode {
    ShowAll,
    HideEmpty,
}

#[component]
pub fn Configurations() -> Element {
    // Handle resource for configuration data
    let mut config_resource = use_resource(get_tedge_config_list);

    // UI state management signals
    let mut opened_sections = use_signal(HashSet::<String>::new);
    let mut search_query = use_signal(String::new);
    let mut filter_mode = use_signal(|| ValueFilterMode::ShowAll);

    // Form editing and feedback signals
    let mut is_editing = use_signal(|| false);
    let mut edit_draft = use_signal(BTreeMap::<String, String>::new);
    let mut error_message = use_signal(|| None::<String>);
    let mut success_message = use_signal(|| None::<String>);
    let mut failed_key = use_signal(|| None::<String>);

    // Handle resource lifetime by cloning data out of the guard
    let map = {
        let resource_guard = config_resource.read();
        let Some(result) = resource_guard.as_ref() else {
            return rsx! { div { class: "loading-spinner", "Loading configurations..." } };
        };
        match result {
            Ok(m) => m.clone(),
            Err(e) => return rsx! { div { class: "error-message", "Error: {e}" } },
        }
    };

    let current_data = if is_editing() {
        edit_draft.read().clone()
    } else {
        map.clone()
    };
    let mut grouped_configs: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let query = search_query.read().to_lowercase();
    let current_filter = *filter_mode.read();

    for (full_key, value) in current_data {
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

    // Ownership management for closures
    let map_for_edit = map.clone();
    let map_for_save = map.clone();
    let map_for_view = map.clone();

    rsx! {
        document::Link { rel: "stylesheet", href: CONFIG_CSS }

        div { class: "config-dashboard",
            // Floating Notifications
            if let Some(msg) = error_message.read().clone() {
                div { class: "toast error-toast animate-fade-in",
                    span { "{msg}" }
                    button { class: "close-btn", onclick: move |_| { error_message.set(None); failed_key.set(None); }, "×" }
                }
            }

            if let Some(msg) = success_message.read().clone() {
                div { class: "toast success-toast animate-fade-in",
                    span { "{msg}" }
                    button {
                        id: "success-close-btn", // Target for JavaScript timer
                        class: "close-btn",
                        onclick: move |_| success_message.set(None),
                        "×"
                    }
                }
            }

            div { class: "header-container",
                h1 {
                    span { class: "title-brand", "thin-edge.io" }
                    "Configuration"
                }

                div { class: "action-group",
                    if !is_editing() {
                        button {
                            class: "btn-primary",
                            onclick: move |_| {
                                error_message.set(None);
                                success_message.set(None);
                                failed_key.set(None);
                                edit_draft.set(map_for_edit.clone());
                                is_editing.set(true);
                            },
                            "✎ Edit Mode"
                        }
                    } else {
                        div { class: "edit-actions",
                            button {
                                class: "btn-success",
                                onclick: move |_| {
                                    let mut updates = BTreeMap::new();
                                    let draft = edit_draft.read();
                                    for (key, val) in draft.iter() {
                                        if map_for_save.get(key) != Some(val) {
                                            updates.insert(key.clone(), val.clone());
                                        }
                                    }

                                    if updates.is_empty() {
                                        is_editing.set(false);
                                        return;
                                    }

                                    // Spawn async task for applying changes
                                    spawn(async move {
                                        match set_tedge_configs(updates).await {
                                            Ok(_) => {
                                                is_editing.set(false);
                                                error_message.set(None);
                                                failed_key.set(None);
                                                success_message.set(Some("✓ Changes saved successfully!".to_string()));
                                                config_resource.restart();

                                                // Using native JS timer via bridge to avoid tokio/gloo in UI
                                                document::eval(r#"
                                                    setTimeout(() => {
                                                        const btn = document.getElementById('success-close-btn');
                                                        if (btn) btn.click();
                                                    }, 3000);
                                                "#);
                                            }
                                            Err(e) => {
                                                let raw = format!("{}", e);
                                                let msg = raw.split("server function:").last().unwrap_or(&raw).trim().to_string();
                                                if let Some((k, _)) = msg.split_once(':') {
                                                    failed_key.set(Some(k.trim().to_string()));
                                                }
                                                error_message.set(Some(msg));
                                            }
                                        }
                                    });
                                },
                                "💾 Save Changes"
                            }
                            button {
                                class: "btn-ghost",
                                onclick: move |_| {
                                    is_editing.set(false);
                                    error_message.set(None);
                                    failed_key.set(None);
                                },
                                "Cancel"
                            }
                        }
                    }
                }
            }

            // Toolbar Area
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

            // List of grouped configurations
            if grouped_configs.is_empty() {
                div { class: "empty-state", "No results found." }
            } else {
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
                                        if opened.contains(&prefix_clone) { opened.remove(&prefix_clone); }
                                        else { opened.insert(prefix_clone.clone()); }
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
                                                let current_key = key.clone();
                                                let current_value = value.clone();
                                                let is_modified = is_editing() && map_for_view.get(&current_key) != Some(&current_value);
                                                let is_error = failed_key.read().as_ref() == Some(&current_key);

                                                rsx! {
                                                    div {
                                                        class: "config-row",
                                                        class: if is_modified { "modified-row" },
                                                        class: if is_error { "error-row" },
                                                        key: "{key}",
                                                        div { class: "cell-key", "{key}" }
                                                        div { class: "cell-value-container",
                                                            if is_editing() {
                                                                input {
                                                                    class: "value-input",
                                                                    class: if is_modified { "modified-input" },
                                                                    class: if is_error { "error-input" },
                                                                    value: "{value}",
                                                                    oninput: move |evt| {
                                                                        edit_draft.write().insert(current_key.clone(), evt.value());
                                                                        if failed_key.read().as_ref() == Some(&current_key) { failed_key.set(None); }
                                                                    }
                                                                }
                                                            } else {
                                                                span { class: "value-text", "{value}" }
                                                                button {
                                                                    class: "copy-btn",
                                                                    onclick: move |_| {
                                                                        let escaped = current_value.replace('\\', "\\\\").replace('"', "\\\"");
                                                                        let js = format!(
                                                                            r##"
                                                                            navigator.clipboard.writeText("{}");
                                                                            const btn = event.target;
                                                                            btn.innerText = "Copied!";
                                                                            btn.style.color = "#10b981";
                                                                            setTimeout(() => {{ btn.innerText = "📋"; btn.style.color = ""; }}, 2000);
                                                                            "##, 
                                                                            escaped
                                                                        );
                                                                        document::eval(&js);
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

#[server]
pub async fn set_tedge_configs(updates: BTreeMap<String, String>) -> Result<(), ServerFnError> {
    // Apply each configuration update in bulk
    for (key, value) in updates {
        let output = tokio::process::Command::new("tedge")
            .args(["config", "set", &key, &value])
            .output()
            .await
            .map_err(|e| ServerFnError::new(format!("Server error {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

            let clean_reason = if let Some((_, detail)) = stderr.split_once("Caused by:") {
                detail.trim()
            } else {
                stderr.trim()
            };
            let final_reason = clean_reason
                .split("(details:")
                .next()
                .unwrap_or(clean_reason)
                .trim();

            return Err(ServerFnError::new(format!("{}: {}", key, final_reason)));
        }
    }
    Ok(())
}
