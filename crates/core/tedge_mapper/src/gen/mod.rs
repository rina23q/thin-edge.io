use crate::core::mapper::start_basic_actors;
use crate::TEdgeComponent;
use tedge_config::TEdgeConfig;
use tedge_gen_mapper::GenMapperBuilder;

pub struct GenMapper;

#[async_trait::async_trait]
impl TEdgeComponent for GenMapper {
    async fn start(
        &self,
        tedge_config: TEdgeConfig,
        _config_dir: &tedge_config::Path,
    ) -> Result<(), anyhow::Error> {
        let (mut runtime, mut mqtt_actor) =
            start_basic_actors("tedge-gen-mapper", &tedge_config).await?;

        let mut gen_mapper = GenMapperBuilder::default();
        gen_mapper.load("/etc/tedge/gen-mapper").await;
        gen_mapper.connect(&mut mqtt_actor);

        runtime.spawn(gen_mapper).await?;
        runtime.spawn(mqtt_actor).await?;
        runtime.run_to_completion().await?;
        Ok(())
    }
}
