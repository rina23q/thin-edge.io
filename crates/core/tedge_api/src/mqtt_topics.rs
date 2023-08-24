//! This module abstracts the MQTT topics used by thin-edge.
//!
//! See https://thin-edge.github.io/thin-edge.io/next/references/mqtt-api/

use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

/// The MQTT topics are represented by three distinct groups:
/// - a root prefix, used by all the topics
/// - an entity topic identifier of the source or target of the messages
/// - a channel kind for the messages exchanged along this topic
///
/// Once built from a root prefix, the main two features of such a schema are to:
/// - get the topic addressing a given entity channel
/// - get the entity channel addressed by some topic
///
/// ```
/// # use tedge_api::mqtt_topics::{MqttSchema, Channel, EntityId};
/// # use mqtt_channel::Topic;
///
/// // The default root prefix is `"te"`:
/// let te = MqttSchema::default();
/// assert_eq!(&te.root, "te");
///
/// // Getting the entity channel addressed by some topic
/// let topic = Topic::new_unchecked("te/device/child001/service/service001/m/measurement_type");
/// let entity = EntityId::new("device/child001/service/service001");
/// let channel = Channel::Measurement {
///     measurement_type: "measurement_type".to_string(),
/// };
/// assert_eq!(
///     te.entity_channel_of(&topic).ok(),
///     Some((entity.clone(), channel.clone()))
/// );
///
/// // Getting the topic to address a specific entity channel
/// assert_eq!(
///     te.topic_for(&entity, &channel).name,
///     topic.name
/// );
/// ```
pub struct MqttSchema {
    pub root: String,
}

/// The default root prefix used by thin-edge is `te`
impl Default for MqttSchema {
    fn default() -> Self {
        MqttSchema::new("te")
    }
}

impl MqttSchema {
    /// Build a new schema using the given root prefix for all topics.
    pub fn new(root: &str) -> Self {
        MqttSchema {
            root: root.to_string(),
        }
    }

    /// Get the topic addressing a given entity channel
    pub fn topic_for(&self, entity: &EntityId, channel: &Channel) -> mqtt_channel::Topic {
        let topic = format!("{}/{}/{}", self.root, entity.0, channel.to_string());
        mqtt_channel::Topic::new(&topic).unwrap()
    }

    /// Get the entity channel addressed by some topic
    pub fn entity_channel_of(
        &self,
        topic: &mqtt_channel::Topic,
    ) -> Result<(EntityId, Channel), EntityTopicError> {
        let entity_topic: EntityTopic = topic.name.parse()?;
        Ok((entity_topic.entity_id, entity_topic.channel))
    }
}

// TODO: read from config
const MQTT_ROOT: &str = "te";

/// A thin-edge entity MQTT topic.
///
/// An entity topic consists of 3 groups: root, entity identifier, and
/// optionally a channel. To be a valid entity topic, a topic must start with a
/// root, and then have its entity identifier and channel (if present) groups
/// successfully parsed.
///
/// ```
/// # use tedge_api::mqtt_topics::{EntityTopic, Channel};
/// let entity_topic: EntityTopic =
///     format!("te/device/child001/service/service001/m/measurement_type")
///         .parse()
///         .unwrap();
/// assert_eq!(entity_topic.entity_id(), "device/child001/service/service001");
/// assert_eq!(entity_topic.channel(), &Channel::Measurement {
///     measurement_type: "measurement_type".to_string(),
/// });
/// ```
///
/// https://thin-edge.github.io/thin-edge.io/next/references/mqtt-api/#topic-scheme
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityTopic {
    entity_id: EntityId,
    channel: Channel,
}

impl EntityTopic {
    pub fn entity_id(&self) -> &str {
        self.entity_id.0.as_str()
    }

    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// Returns a device name if entity topic identifier is not using a custom
    /// schema.
    pub fn device_name(&self) -> Option<&str> {
        match self.entity_id.0.split('/').collect::<Vec<&str>>()[..] {
            ["device", device_id, "service", _] => Some(device_id),
            ["device", device_id, "", ""] => Some(device_id),
            _ => None,
        }
    }

    /// Returns a service name if entity topic identifier is not using a custom
    /// schema and the entity identifier refers to the service.
    pub fn service_name(&self) -> Option<&str> {
        match self.entity_id.0.split('/').collect::<Vec<&str>>()[..] {
            ["device", _, "service", service_id] => Some(service_id),
            _ => None,
        }
    }

    pub fn is_measurement(topic: &mqtt_channel::Topic) -> bool {
        EntityTopic::from_str(&topic.name)
            .map(|ref t| matches!(t.channel(), Channel::Measurement { .. }))
            .unwrap_or(false)
    }
}

impl FromStr for EntityTopic {
    type Err = EntityTopicError;

    fn from_str(topic: &str) -> Result<Self, Self::Err> {
        const ENTITY_ID_SEGMENTS: usize = 4;

        let (root, topic) = topic.split_once('/').ok_or(EntityTopicError::Root {
            expected: MQTT_ROOT.to_string(),
            got: topic.to_string(),
        })?;
        if root != MQTT_ROOT {
            return Err(EntityTopicError::Root {
                expected: MQTT_ROOT.to_string(),
                got: root.to_string(),
            });
        }

        let mut topic_separator_indices = topic.match_indices('/').map(|(i, _)| i);
        let id_channel_separator_index = topic_separator_indices.nth(3).unwrap_or(topic.len());

        let (entity_id, channel) = topic.split_at(id_channel_separator_index);

        let entity_id_segments = entity_id.matches('/').count();
        let missing_slashes = ENTITY_ID_SEGMENTS - entity_id_segments - 1;
        let entity_id = format!("{entity_id}{:/<1$}", "", missing_slashes);

        let channel: Channel = channel.trim_start_matches('/').parse()?;
        Ok(EntityTopic {
            entity_id: EntityId(entity_id.to_string()),
            channel,
        })
    }
}

impl TryFrom<&mqtt_channel::Topic> for EntityTopic {
    type Error = EntityTopicError;

    fn try_from(topic: &mqtt_channel::Topic) -> Result<Self, Self::Error> {
        topic.name.parse()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum EntityTopicError {
    #[error("Fist topic segment expected to be {expected:?}, got {got:?}")]
    Root { expected: String, got: String },

    #[error("Channel group invalid")]
    Channel(#[from] ChannelError),
}

/// Represents an entity identifier group in thin-edge MQTT scheme.
///
/// An entity identifier is a fixed 4-segment group, as such any 4 topic
/// segments that come after the root are considered a part of an identifier,
/// even if they contain values usually present in the channel group, e.g.
/// `/m/`.
///
/// If the topic ends before the expected 4 segments, the remaining segments are
/// filled by empty segments (`//`).
///
/// # Example
///
///
/// https://thin-edge.github.io/thin-edge.io/next/references/mqtt-api/#group-identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityId(String);

impl EntityId {
    pub fn new(topic_id: &str) -> Self {
        EntityId(topic_id.to_string())
    }
}

/// A channel identifies the type of the messages exchanged over a topic
///
/// <https://thin-edge.github.io/thin-edge.io/next/references/mqtt-api/#group-channel>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    EntityMetadata,
    Measurement { measurement_type: String },
    Event { event_type: String },
    Alarm { alarm_type: String },
    Command { operation: String, cmd_id: String },
    MeasurementMetadata { measurement_type: String },
    EventMetadata { event_type: String },
    AlarmMetadata { alarm_type: String },
    CommandMetadata { operation: String },
}

impl FromStr for Channel {
    type Err = ChannelError;

    fn from_str(channel: &str) -> Result<Self, ChannelError> {
        match channel.split('/').collect::<Vec<&str>>()[..] {
            [""] => Ok(Channel::EntityMetadata),

            ["m", measurement_type] => Ok(Channel::Measurement {
                measurement_type: measurement_type.to_string(),
            }),
            ["m", measurement_type, "meta"] => Ok(Channel::MeasurementMetadata {
                measurement_type: measurement_type.to_string(),
            }),

            ["e", event_type] => Ok(Channel::Event {
                event_type: event_type.to_string(),
            }),
            ["e", event_type, "meta"] => Ok(Channel::EventMetadata {
                event_type: event_type.to_string(),
            }),

            ["a", alarm_type] => Ok(Channel::Alarm {
                alarm_type: alarm_type.to_string(),
            }),
            ["a", alarm_type, "meta"] => Ok(Channel::AlarmMetadata {
                alarm_type: alarm_type.to_string(),
            }),

            ["cmd", operation] => Ok(Channel::CommandMetadata {
                operation: operation.to_string(),
            }),
            ["cmd", operation, cmd_id] => Ok(Channel::Command {
                operation: operation.to_string(),
                cmd_id: cmd_id.to_string(),
            }),

            _ => Err(ChannelError::InvalidCategory(channel.to_string())),
        }
    }
}

impl Display for Channel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Channel::EntityMetadata => Ok(()),

            Channel::Measurement { measurement_type } => write!(f, "m/{measurement_type}"),
            Channel::MeasurementMetadata { measurement_type } => {
                write!(f, "m/{measurement_type}/meta")
            }

            Channel::Event { event_type } => write!(f, "e/{event_type}"),
            Channel::EventMetadata { event_type } => write!(f, "e/{event_type}/meta"),

            Channel::Alarm { alarm_type } => write!(f, "a/{alarm_type}"),
            Channel::AlarmMetadata { alarm_type } => write!(f, "a/{alarm_type}/meta"),

            Channel::Command { operation, cmd_id } => write!(f, "cmd/{operation}/{cmd_id}"),
            Channel::CommandMetadata { operation } => write!(f, "cmd/{operation}"),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ChannelError {
    #[error("Channel needs to have at least 2 segments")]
    TooShort,

    #[error("Invalid category: {0:?}")]
    InvalidCategory(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_correct_topic() {
        let entity_topic: EntityTopic =
            format!("{MQTT_ROOT}/device/child001/service/service001/m/measurement_type")
                .parse()
                .unwrap();

        assert_eq!(
            entity_topic,
            EntityTopic {
                entity_id: EntityId("device/child001/service/service001".to_string()),
                channel: Channel::Measurement {
                    measurement_type: "measurement_type".to_string(),
                }
            }
        );
    }

    #[test]
    fn parses_nochannel_correct_topic() {
        let topic1: EntityTopic = format!("{MQTT_ROOT}/device/child001/service/service001")
            .parse()
            .unwrap();

        let topic = EntityTopic {
            entity_id: EntityId("device/child001/service/service001".to_string()),
            channel: Channel::EntityMetadata,
        };

        assert_eq!(topic1, topic);
    }

    #[test]
    fn parses_noservice_entity_correct_topic() {
        let topic1: EntityTopic = format!("{MQTT_ROOT}/device/child001//").parse().unwrap();
        let topic2: EntityTopic = format!("{MQTT_ROOT}/device/child001").parse().unwrap();

        let topic = EntityTopic {
            entity_id: EntityId("device/child001//".to_string()),
            channel: Channel::EntityMetadata,
        };

        assert_eq!(topic1, topic);
        assert_eq!(topic2, topic);
    }

    #[test]
    fn no_root() {
        let topic = "device/child001/service/service001/m/measurement_type".parse::<EntityTopic>();

        assert!(topic.is_err());
    }

    #[test]
    fn incorrect_channel() {
        let topic1 = format!(
            "{MQTT_ROOT}/device/child001/service/service001/incorrect_category/measurement_type"
        )
        .parse::<EntityTopic>();

        let topic2 =
            format!("{MQTT_ROOT}/device/child001/service/service001/m").parse::<EntityTopic>();

        assert!(topic1.is_err());
        assert!(topic2.is_err());
    }
}
