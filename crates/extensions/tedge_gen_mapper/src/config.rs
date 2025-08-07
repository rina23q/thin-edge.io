use crate::js_filter::JsFilter;
use crate::js_runtime::JsRuntime;
use crate::pipeline::Pipeline;
use crate::pipeline::Stage;
use crate::LoadError;
use camino::Utf8PathBuf;
use serde::Deserialize;
use serde_json::Value;
use std::path::Path;
use tedge_mqtt_ext::TopicFilter;

#[derive(Deserialize)]
pub struct PipelineConfig {
    input_topics: Vec<String>,
    stages: Vec<StageConfig>,
}

#[derive(Deserialize)]
pub struct StageConfig {
    filter: FilterSpec,

    #[serde(default)]
    config: Option<Value>,

    #[serde(default)]
    tick_every_seconds: u64,

    #[serde(default)]
    meta_topics: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum FilterSpec {
    JavaScript(Utf8PathBuf),
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("Not a valid MQTT topic filter: {0}")]
    IncorrectTopicFilter(String),

    #[error(transparent)]
    LoadError(#[from] LoadError),
}

impl PipelineConfig {
    pub fn from_filter(filter: Utf8PathBuf) -> Self {
        let input_topic = "#".to_string();
        let stage = StageConfig {
            filter: FilterSpec::JavaScript(filter),
            config: None,
            tick_every_seconds: 1,
            meta_topics: vec![],
        };
        Self {
            input_topics: vec![input_topic],
            stages: vec![stage],
        }
    }

    pub fn compile(
        self,
        js_runtime: &JsRuntime,
        config_dir: &Path,
        source: Utf8PathBuf,
    ) -> Result<Pipeline, ConfigError> {
        let input = topic_filters(&self.input_topics)?;
        let stages = self
            .stages
            .into_iter()
            .map(|stage| stage.compile(js_runtime, config_dir))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Pipeline {
            input_topics: input,
            stages,
            source,
        })
    }
}

impl StageConfig {
    pub fn compile(self, _js_runtime: &JsRuntime, config_dir: &Path) -> Result<Stage, ConfigError> {
        let path = match self.filter {
            FilterSpec::JavaScript(path) if path.is_absolute() => path.into(),
            FilterSpec::JavaScript(path) if path.starts_with(config_dir) => path.into(),
            FilterSpec::JavaScript(path) => config_dir.join(path),
        };
        let filter = JsFilter::new(path)
            .with_config(self.config)
            .with_tick_every_seconds(self.tick_every_seconds);
        let config_topics = topic_filters(&self.meta_topics)?;
        Ok(Stage {
            filter,
            config_topics,
        })
    }
}

fn topic_filters(patterns: &Vec<String>) -> Result<TopicFilter, ConfigError> {
    let mut topics = TopicFilter::empty();
    for pattern in patterns {
        topics
            .add(pattern.as_str())
            .map_err(|_| ConfigError::IncorrectTopicFilter(pattern.clone()))?;
    }
    Ok(topics)
}
