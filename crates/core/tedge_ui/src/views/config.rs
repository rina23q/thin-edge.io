use dioxus::prelude::*;
use std::collections::BTreeMap;
use std::collections::HashSet;

#[cfg(feature = "server")]
use std::process::Stdio;
#[cfg(feature = "server")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "server")]
use tokio::process::Command;

const CONFIG_CSS: Asset = asset!("/assets/styling/config.css");

// Define an enum to handle different filtering modes for better scalability
#[derive(Copy, Clone, PartialEq, Eq)]
enum ValueFilterMode {
    ShowAll,
    HideEmpty,
}

#[component]
pub fn Configurations() -> Element {
    // Resource to fetch tedge config from the server
    let mut config_resource = use_resource(get_tedge_config_list);

    // UI state for managing interaction
    let mut opened_sections = use_signal(HashSet::<String>::new);
    let mut search_query = use_signal(String::new);
    let mut filter_mode = use_signal(|| ValueFilterMode::ShowAll);

    // States for editing mode and operational feedback
    let mut is_editing = use_signal(|| false);
    let mut edit_draft = use_signal(BTreeMap::<String, String>::new);
    let mut error_message = use_signal(|| None::<String>);
    let mut success_message = use_signal(|| None::<String>);
    let mut failed_key = use_signal(|| None::<String>);
    let mut sudo_password = use_signal(String::new);

    // Safely extract data while managing borrow lifecycles
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

    // Ownership transfer preparation for closures
    let map_for_edit = map.clone();
    let map_for_save = map.clone();
    let map_for_view = map.clone();

    rsx! {
        document::Link { rel: "stylesheet", href: CONFIG_CSS }

        div { class: "config-dashboard",
            // Toast notifications for Success/Error
            if let Some(msg) = error_message.read().clone() {
                div { class: "toast error-toast animate-fade-in", span { "{msg}" }
                    button { class: "close-btn", onclick: move |_| { error_message.set(None); failed_key.set(None); }, "×" }
                }
            }
            if let Some(msg) = success_message.read().clone() {
                div { class: "toast success-toast animate-fade-in", span { "{msg}" }
                    button { id: "success-close-btn", class: "close-btn", onclick: move |_| success_message.set(None), "×" }
                }
            }

            // --- HEADER: Title and Global Actions ---
            div { class: "header-container",
                h1 {
                    span { class: "title-brand", "thin-edge.io" }
                    "Configuration"
                }

                div { class: "action-group",
                    input {
                        type: "password", class: "sudo-input", placeholder: "Sudo password",
                        value: "{sudo_password}", oninput: move |evt| sudo_password.set(evt.value())
                    }

                    if !is_editing() {
                        button { class: "btn-primary",
                            onclick: move |_| {
                                error_message.set(None); success_message.set(None);
                                edit_draft.set(map_for_edit.clone()); is_editing.set(true);
                            },
                            "✎ Edit Mode"
                        }
                    } else {
                        div { class: "edit-actions",
                            button { class: "btn-success",
                                onclick: move |_| {
                                    let mut updates = BTreeMap::new();
                                    let draft = edit_draft.read();
                                    for (k, v) in draft.iter() {
                                        if map_for_save.get(k) != Some(v) { updates.insert(k.clone(), v.clone()); }
                                    }
                                    if updates.is_empty() { is_editing.set(false); return; }
                                    let pwd = if sudo_password.read().is_empty() { None } else { Some(sudo_password.read().clone()) };
                                    spawn(async move {
                                        match set_tedge_configs(updates, pwd).await {
                                            Ok(_) => {
                                                is_editing.set(false);  error_message.set(None); failed_key.set(None);
                                                success_message.set(Some("✓ Saved successfully!".to_string()));
                                                config_resource.restart();
                                                document::eval("setTimeout(() => { document.getElementById('success-close-btn')?.click(); }, 3000);");
                                            }
                                            Err(e) => {
                                                let raw = format!("{}", e);
                                                let msg = raw.split("server function:").last().unwrap_or(&raw).trim().to_string();
                                                if let Some((k, _)) = msg.split_once(':') { failed_key.set(Some(k.trim().to_string())); }
                                                error_message.set(Some(msg));
                                            }
                                        }
                                    });
                                },
                                "💾 Save Changes"
                            }
                            button { class: "btn-ghost", onclick: move |_| { is_editing.set(false); error_message.set(None); failed_key.set(None); }, "Cancel" }
                        }
                    }
                }
            }

            // --- TOOLBAR: Search and Filter ---
            div { class: "toolbar",
                div { class: "search-box", span { class: "search-icon", "🔍" }
                    input { class: "search-input", placeholder: "Search keys or values...",
                        value: "{search_query}", oninput: move |evt| search_query.set(evt.value()) }
                }
                div { class: "filter-box", label { class: "filter-label", "Filter:" }
                    select { class: "filter-select", onchange: move |evt| {
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

            // --- LIST: 3-Column Grid + Right-Aligned Arrows ---
            if grouped_configs.is_empty() {
                div { class: "empty-state", "No configurations match your search." }
            } else {
                for (prefix, items) in grouped_configs {
                    {
                        let is_open = opened_sections.read().contains(&prefix);
                        let prefix_clone = prefix.clone();
                        rsx! {
                            section { class: "config-section", key: "{prefix}",
                                div { class: "section-header clickable", onclick: move |_| {
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
                                                let key_to_unset = key.clone();
                                                let current_value = value.clone();

                                                // Individual clones for each closure to fix E0382
                                                // let k_for_input = current_key.clone();
                                                // let k_for_reset = current_key.clone();
                                                // let k_for_copy = current_key.clone();
                                                // let v_for_copy = current_value.clone();

                                                let is_modified = is_editing() && map_for_view.get(&current_key) != Some(&current_value);
                                                let is_error = failed_key.read().as_ref() == Some(&current_key);

                                                rsx! {
                                                    div { class: "config-row", class: if is_modified { "modified-row" }, class: if is_error { "error-row" }, key: "{key}",
                                                        div { class: "cell-key", "{current_key}" }
                                                        div { class: "cell-value",
                                                            if is_editing() {
                                                                input { class: "value-input", class: if is_error { "error-input" },
                                                                    value: "{current_value}",
                                                                    oninput: move |evt| {
                                                                        edit_draft.write().insert(current_key.clone(), evt.value());
                                                                        if failed_key.read().as_ref() == Some(&current_key) { failed_key.set(None); }
                                                                    }
                                                                }
                                                            } else {
                                                                span { class: "value-text", "{current_value}" }
                                                            }
                                                        }
                                                        div { class: "cell-actions",
                                                            if !is_editing() {
                                                                button { class: "action-btn reset-btn", title: "Unset to Default",
                                                                    onclick: move |_| {
                                                                        let key_to_unset = key_to_unset.clone();
                                                                        let pwd = if sudo_password.read().is_empty() { None } else { Some(sudo_password.read().clone()) };
                                                                        spawn(async move {
                                                                            if unset_tedge_config(key_to_unset.clone(), pwd).await.is_ok() {
                                                                                success_message.set(Some(format!("✓ Unset: {}", key_to_unset)));
                                                                                config_resource.restart();
                                                                                document::eval("setTimeout(() => { document.getElementById('success-close-btn')?.click(); }, 3000);");
                                                                            }
                                                                        });
                                                                    }, "↺"
                                                                }
                                                                button { class: "action-btn copy-btn", title: "Copy to Dashboard",
                                                                    onclick: move |_| {
                                                                        let escaped = current_value.replace('\\', "\\\\").replace('"', "\\\"");
                                                                        let js = format!(
                                                                            r##"
                                                                            navigator.clipboard.writeText("{}");
                                                                            // Robust target detection (handles click on icon)
                                                                            const btn = event.target.closest('button');
                                                                            if (btn) {{
                                                                                const oldText = btn.innerText;
                                                                                btn.innerText = "Copied!";
                                                                                btn.classList.add('copy-success');
                                                                                setTimeout(() => {{ 
                                                                                    btn.innerText = oldText; 
                                                                                    btn.classList.remove('copy-success'); 
                                                                                }}, 2000);
                                                                            }}
                                                                            "##, 
                                                                            escaped
                                                                        );
                                                                        document::eval(&js);
                                                                    }, "📋"
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
pub async fn set_tedge_configs(
    updates: BTreeMap<String, String>,
    password: Option<String>, // Optional sudo password
) -> Result<(), ServerFnError> {
    for (key, value) in updates {
        let mut cmd = if let Some(ref pwd) = password {
            // If password is provided, use 'sudo -S'
            let mut c = Command::new("sudo");
            c.args(["-S", "tedge", "config", "set", &key, &value]);
            c.stdin(Stdio::piped());
            c.stderr(Stdio::piped());
            c
        } else {
            // Otherwise run directly
            let mut c = Command::new("tedge");
            c.args(["config", "set", &key, &value]);
            c.stderr(Stdio::piped());
            c
        };

        let mut child = cmd
            .spawn()
            .map_err(|e| ServerFnError::new(format!("Failed to spawn command: {}", e)))?;

        // Write password to stdin if using sudo
        if let (Some(ref pwd), Some(mut stdin)) = (password.as_ref(), child.stdin.take()) {
            stdin
                .write_all(format!("{}\n", pwd).as_bytes())
                .await
                .map_err(|e| ServerFnError::new(format!("Failed to write password: {}", e)))?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| ServerFnError::new(format!("Execution error: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ServerFnError::new(format!("{}: {}", key, stderr.trim())));
        }
    }
    Ok(())
}

#[server]
pub async fn unset_tedge_config(
    key: String,
    password: Option<String>,
) -> Result<(), ServerFnError> {
    let mut cmd = if let Some(ref pwd) = password {
        let mut c = Command::new("sudo");
        c.args(["-S", "tedge", "config", "unset", &key]);
        c.stdin(Stdio::piped());
        c.stderr(Stdio::piped());
        c
    } else {
        let mut c = Command::new("tedge");
        c.args(["config", "unset", &key]);
        c.stderr(Stdio::piped());
        c
    };

    let mut child = cmd
        .spawn()
        .map_err(|e| ServerFnError::new(format!("{}", e)))?;

    if let (Some(ref pwd), Some(mut stdin)) = (password.as_ref(), child.stdin.take()) {
        stdin
            .write_all(format!("{}\n", pwd).as_bytes())
            .await
            .map_err(|e| ServerFnError::new(format!("Input error: {}", e)))?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| ServerFnError::new(format!("Wait failed: {}", e)))?;
    if !output.status.success() {
        return Err(ServerFnError::new(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    Ok(())
}
