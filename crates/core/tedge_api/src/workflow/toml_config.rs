use crate::workflow::ExitHandlers;
use crate::workflow::GenericStateUpdate;
use crate::workflow::ScriptDefinitionError;
use crate::workflow::ShellScript;
use serde::de::Error;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Write;
use std::num::ParseIntError;
use std::str::FromStr;

/// User-friendly representation of an [OperationWorkflow]
///
/// The user view of an operation workflow configured using a TOML file.
#[derive(Clone, Debug, Deserialize)]
pub struct TomlOperationWorkflow {
    /// The operation to which this workflow applies
    pub operation: String,

    /// Default handlers used to determine the next state from an action outcome
    #[serde(flatten)]
    pub handlers: TomlExitHandlers,

    /// The states of the state machine
    #[serde(flatten)]
    pub states: HashMap<String, TomlOperationState>,
}

/// User-friendly representation of an [OperationState]
#[derive(Clone, Debug, Deserialize)]
pub struct TomlOperationState {
    /// The action driving the operation when in that state
    #[serde(flatten)]
    pub action: TomlOperationAction,

    /// Handlers used to determine the next state from the action outcome
    #[serde(flatten)]
    pub handlers: TomlExitHandlers,
}

/// User-friendly representation of an [OperationAction]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TomlOperationAction {
    Script(ShellScript),
    BackgroundScript(ShellScript),
    BuiltinAction(ShellScript),
}

/// User-friendly representation of a [GenericStateUpdate]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum TomlStateUpdate {
    /// In the simple format, only a status is specified, eg.
    /// `on_error = "<status>"`
    Simple(String),
    /// The simple format is equivalent to a detailed command update
    /// specifying only a status, eg.
    /// `on_error = { status = "<status>" }`
    Detailed(GenericStateUpdate),
}

impl From<TomlStateUpdate> for GenericStateUpdate {
    fn from(value: TomlStateUpdate) -> Self {
        match value {
            TomlStateUpdate::Simple(status) => GenericStateUpdate {
                status,
                reason: None,
            },
            TomlStateUpdate::Detailed(update) => update,
        }
    }
}

/// User-Friendly representation of an [ExitHandlers]; as used in the operation TOML definition files
///
/// A user don't have to give a handler for all possible exit code.
/// - A handler can simply be a string used as the next state for the command.
/// - A handler can be attached to a range of exit code
/// - A wildcard handler can be defined as a default handler
/// - `on_success` is syntactic sugar for `on_exit.0`
/// - `on_error` is syntactic sugar for `on_exit._`
///
/// Some combinations are not valid and are rejected when the operation model is built from its TOML representation.
/// - `on_success` and `on_exit.0` are are synonyms and cannot be both provided
/// - `on_error` and `on_exit._` are are synonyms and cannot be both provided
/// - `on_success` and `from_stdout` are incompatible, as the next state is either determined from the script stdout or its exit codes
/// - `on_exec` is only meaningful in the context of a background script or a builtin action
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct TomlExitHandlers {
    #[serde(skip_serializing_if = "Option::is_none")]
    on_success: Option<TomlStateUpdate>,

    #[serde(skip_serializing_if = "Option::is_none")]
    on_error: Option<TomlStateUpdate>,

    #[serde(skip_serializing_if = "Option::is_none")]
    on_kill: Option<TomlStateUpdate>,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    on_exit: HashMap<ExitCodes, TomlStateUpdate>,

    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_second: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    on_timeout: Option<TomlStateUpdate>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    from_stdout: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    on_exec: Option<TomlStateUpdate>,
}

impl TryFrom<TomlExitHandlers> for ExitHandlers {
    type Error = ScriptDefinitionError;

    fn try_from(value: TomlExitHandlers) -> Result<Self, Self::Error> {
        let on_error = value.on_error.map(|u| u.into());
        let on_success = value.on_success.map(|u| u.into());
        let on_kill = value.on_kill.map(|u| u.into());
        let wildcard = value
            .on_exit
            .get(&ExitCodes::AnyError)
            .map(|u| u.clone().into());
        let on_exit: Vec<(u8, u8, GenericStateUpdate)> = value
            .on_exit
            .into_iter()
            .filter_map(|(code, state)| {
                let state = state.into();
                match code {
                    ExitCodes::Code(x) => Some((x, x, state)),
                    ExitCodes::Range { from, to } => Some((from, to, state)),
                    ExitCodes::AnyError => None,
                }
            })
            .collect();

        ExitHandlers::try_new(on_exit, on_success, on_error, on_kill, wildcard)
    }
}

/// Represent either:
/// - a specific exit code
/// - a range of exit codes
/// - any non-zero code
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum ExitCodes {
    Code(u8),
    Range { from: u8, to: u8 },
    AnyError,
}

impl<'de> Deserialize<'de> for ExitCodes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let exit_code = String::deserialize(deserializer)?;
        exit_code
            .parse()
            .map_err(|err| D::Error::custom(format!("invalid exit: {exit_code}: {err}")))
    }
}

impl Serialize for ExitCodes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl Display for ExitCodes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitCodes::Code(x) => x.fmt(f),
            ExitCodes::Range { from, to } => {
                from.fmt(f)?;
                f.write_char('-')?;
                to.fmt(f)
            }
            ExitCodes::AnyError => f.write_char('_'),
        }
    }
}

impl FromStr for ExitCodes {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "_" {
            return Ok(ExitCodes::AnyError);
        }

        match s.split_once('-') {
            None => Ok(ExitCodes::Code(s.parse()?)),
            Some((from, to)) => Ok(ExitCodes::Range {
                from: from.parse()?,
                to: to.parse()?,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::GenericStateUpdate;
    use ExitCodes::*;

    #[test]
    fn parse_exit_handlers() {
        let file = r#"
on_exit.0 = "next_state"                                  # next state for an exit status
on_exit.1 = { status = "retry_state", reason = "busy"}    # next status with fields
on_exit.2-5 = { status = "fatal_state", reason = "oops"}  # next state for a range of exit status
on_exit._ = "failed"                                      # wildcard for any other non successfull exit
on_kill = { status = "failed", reason = "killed"}         # next status when killed
        "#;
        let input: TomlExitHandlers = toml::from_str(file).unwrap();
        assert_eq!(
            input,
            TomlExitHandlers {
                on_success: None,
                on_error: None,
                on_kill: Some(TomlStateUpdate::Detailed(GenericStateUpdate {
                    status: "failed".to_string(),
                    reason: Some("killed".to_string())
                })),
                on_exit: HashMap::from_iter([
                    (Code(0), TomlStateUpdate::Simple("next_state".to_string())),
                    (
                        Code(1),
                        TomlStateUpdate::Detailed(GenericStateUpdate {
                            status: "retry_state".to_string(),
                            reason: Some("busy".to_string())
                        })
                    ),
                    (
                        Range { from: 2, to: 5 },
                        TomlStateUpdate::Detailed(GenericStateUpdate {
                            status: "fatal_state".to_string(),
                            reason: Some("oops".to_string())
                        })
                    ),
                    (AnyError, TomlStateUpdate::Simple("failed".to_string())),
                ]),
                timeout_second: None,
                on_timeout: None,
                from_stdout: Vec::new(),
                on_exec: None,
            }
        )
    }

    #[test]
    fn get_state_update_from_exit_status() {
        let file = r#"
on_exit.0 = "0"
on_exit.3-5 = "3-5"
on_exit._ = "wildcard"
on_kill = "killed"
on_exit.1 = "1"
        "#;
        let input: TomlExitHandlers = toml::from_str(file).unwrap();
        let handlers: ExitHandlers = input.try_into().unwrap();
        assert_eq!(handlers.state_update_on_success().status, "0");
        assert_eq!(handlers.state_update_on_exit(0).status, "0");
        assert_eq!(handlers.state_update_on_exit(1).status, "1");
        assert_eq!(handlers.state_update_on_exit(2).status, "wildcard");
        assert_eq!(handlers.state_update_on_exit(3).status, "3-5");
        assert_eq!(handlers.state_update_on_exit(4).status, "3-5");
        assert_eq!(handlers.state_update_on_exit(5).status, "3-5");
        assert_eq!(handlers.state_update_on_exit(6).status, "wildcard");
        assert_eq!(handlers.state_update_on_kill(9).status, "killed");
    }

    #[test]
    fn forbid_duplicated_success_handler() {
        let file = r#"
on_exit.0 = "0"
on_success = "success"
        "#;
        let input: TomlExitHandlers = toml::from_str(file).unwrap();
        let error = TryInto::<ExitHandlers>::try_into(input).unwrap_err();
        assert_eq!(error, ScriptDefinitionError::DuplicatedOnSuccessHandler)
    }

    #[test]
    fn forbid_duplicated_error_handler() {
        let file = r#"
on_exit._ = "wildcard"
on_error = "error"
        "#;
        let input: TomlExitHandlers = toml::from_str(file).unwrap();
        let error = TryInto::<ExitHandlers>::try_into(input).unwrap_err();
        assert_eq!(error, ScriptDefinitionError::DuplicatedOnErrorHandler)
    }

    #[test]
    fn forbid_overlapping_error_handler() {
        let file = r#"
on_exit.1-5 = "1-5"
on_exit.4-8 = "4-8"
        "#;
        let input: TomlExitHandlers = toml::from_str(file).unwrap();
        let error = TryInto::<ExitHandlers>::try_into(input).unwrap_err();
        assert_eq!(
            error,
            ScriptDefinitionError::OverlappingHandler {
                first: "1-5".to_string(),
                second: "4-8".to_string()
            }
        )
    }

    #[test]
    fn forbid_ill_defined_range() {
        let file = r#"
on_exit.5-1 = "oops"
        "#;
        let input: TomlExitHandlers = toml::from_str(file).unwrap();
        let error = TryInto::<ExitHandlers>::try_into(input).unwrap_err();
        assert_eq!(
            error,
            ScriptDefinitionError::IncorrectRange { from: 5, to: 1 }
        )
    }

    #[test]
    fn default_handlers() {
        let file = "";
        let input: TomlExitHandlers = toml::from_str(file).unwrap();
        let handlers = TryInto::<ExitHandlers>::try_into(input).unwrap();
        assert_eq!(handlers.state_update_on_success().status, "successful");
        assert_eq!(
            handlers.state_update_on_exit(1).reason.unwrap(),
            "returned exit code 1"
        );
        assert_eq!(
            handlers.state_update_on_kill(9).reason.unwrap(),
            "killed by signal 9"
        );
    }

    #[test]
    fn parse_operation_toml() {
        let file = r#"
operation = "check"
timeout_second = 3600
on_timeout = "timeout"

[step1]
script = "/home/pi/step1.sh"
on_success = "step2"

[step2]
background_script = "/home/pi/reboot.sh arg1 arg2"
on_next = "step3"

[step3]
builtin_action = "waiting /home/pi/reboot.sh"
on_success = "successful_reboot"
on_error = "failed_reboot"
"#;
        let input: TomlOperationWorkflow = toml::from_str(file).unwrap();
        assert_eq!(input.operation, "check");
        assert_eq!(input.handlers.timeout_second, Some(3600));
        assert_eq!(
            input.handlers.on_timeout,
            Some(TomlStateUpdate::Simple("timeout".to_string()))
        );
    }
}
