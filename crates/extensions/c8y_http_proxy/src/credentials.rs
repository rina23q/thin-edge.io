use async_trait::async_trait;
use c8y_api::http_proxy::C8yMqttJwtTokenRetriever;
use c8y_api::http_proxy::JwtError;
use tedge_actors::ClientMessageBox;
use tedge_actors::Sequential;
use tedge_actors::Server;
use tedge_actors::ServerActorBuilder;
use tedge_actors::ServerConfig;
use tedge_config::TopicPrefix;

pub type JwtRequest = ();
pub type JwtResult = Result<String, JwtError>;

/// Retrieves JWT tokens authenticating the device
pub type JwtRetriever = ClientMessageBox<JwtRequest, JwtResult>;

/// A JwtRetriever that gets JWT tokens from C8Y over MQTT
pub struct C8YJwtRetriever {
    mqtt_retriever: C8yMqttJwtTokenRetriever,
}

impl C8YJwtRetriever {
    pub fn builder(
        mqtt_config: mqtt_channel::Config,
        topic_prefix: TopicPrefix,
    ) -> ServerActorBuilder<C8YJwtRetriever, Sequential> {
        let mqtt_retriever = C8yMqttJwtTokenRetriever::new(mqtt_config, topic_prefix);
        let server = C8YJwtRetriever { mqtt_retriever };
        ServerActorBuilder::new(server, &ServerConfig::default(), Sequential)
    }
}

#[async_trait]
impl Server for C8YJwtRetriever {
    type Request = JwtRequest;
    type Response = JwtResult;

    fn name(&self) -> &str {
        "C8YJwtRetriever"
    }

    async fn handle(&mut self, _request: Self::Request) -> Self::Response {
        let response = self.mqtt_retriever.get_jwt_token().await?;
        let auth_value = format!("Bearer {}", response.token());
        Ok(auth_value)
    }
}

/// Return fixed Basic auth value
pub struct C8YBasicAuthProvider {
    username: String,
    password: String,
}

impl C8YBasicAuthProvider {
    pub fn builder(
        username: &str,
        password: &str,
    ) -> ServerActorBuilder<C8YBasicAuthProvider, Sequential> {
        let server = C8YBasicAuthProvider {
            username: username.into(),
            password: password.into(),
        };
        ServerActorBuilder::new(server, &ServerConfig::default(), Sequential)
    }
}

#[async_trait]
impl Server for C8YBasicAuthProvider {
    type Request = JwtRequest;
    type Response = JwtResult;

    fn name(&self) -> &str {
        "C8YBasicAuthProvider"
    }

    async fn handle(&mut self, _request: Self::Request) -> Self::Response {
        Ok(format!(
            "Basic {}",
            base64::encode(format!("{}:{}", self.username, self.password))
        ))
    }
}

/// A JwtRetriever that simply always returns the same JWT token (possibly none)
#[cfg(test)]
pub(crate) struct ConstJwtRetriever {
    pub token: String,
}

#[async_trait]
#[cfg(test)]
impl Server for ConstJwtRetriever {
    type Request = JwtRequest;
    type Response = JwtResult;

    fn name(&self) -> &str {
        "ConstJwtRetriever"
    }

    async fn handle(&mut self, _request: Self::Request) -> Self::Response {
        Ok(self.token.clone())
    }
}
