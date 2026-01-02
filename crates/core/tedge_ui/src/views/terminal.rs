use dioxus::prelude::*;

const TERMINAL_CSS: Asset = asset!("/assets/styling/terminal.css");

// backend
#[server]
pub async fn run_tedge_command(input: String) -> Result<String, ServerFnError> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return Ok("".to_string());
    }

    let output = std::process::Command::new(parts[0])
        .args(&parts[1..])
        .output()
        .map_err(|e| ServerFnError::new(&format!("コマンド実行失敗: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(stdout)
    } else {
        Ok(format!("Error: {}", stderr))
    }
}

// frontend
#[component]
pub fn Terminal() -> Element {
    let mut history = use_signal(|| {
        vec![
            "Welcome to tedge Web Terminal".to_string(),
            "Type 'tedge config list' to start...".to_string(),
        ]
    });
    let mut current_input = use_signal(|| "".to_string());

    let on_submit = move |_| {
        spawn(async move {
            let cmd = current_input.read().clone();
            if cmd.is_empty() {
                return;
            }

            history.write().push(format!("$ {}", cmd));
            current_input.set("".to_string());

            match run_tedge_command(cmd).await {
                Ok(result) => {
                    for line in result.lines() {
                        history.write().push(line.to_string());
                    }
                }
                Err(e) => {
                    history.write().push(format!("System Error: {}", e));
                }
            }
        });
    };

    rsx! {
        document::Link { rel: "stylesheet", href: TERMINAL_CSS }
        div { class: "terminal-container",
            div { class: "terminal-history",
                for line in history.read().iter() {
                    div { class: "terminal-line", "{line}" }
                }
            }

            div { class: "terminal-input-wrapper",
                span { class: "terminal-prompt", "$" }
                input {
                    class: "terminal-input",
                    value: "{current_input}",
                    autofocus: true,
                    oninput: move |evt| current_input.set(evt.value()),
                    onkeydown: move |evt| {
                        if evt.key() == Key::Enter {
                            on_submit(());
                        }
                    },
                }
            }
        }
    }
}
