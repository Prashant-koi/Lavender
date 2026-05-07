pub struct Publisher {
    client: async_nats::Client,
    telemetry_subject_prefix: String,
    heartbeat_subject_prefix: String,
    tenant_id: String,
}

impl Publisher {
    // We connect once at startup and reuse the client for all telemetry publishes.
    pub async fn connect(
        nats_url: &str,
        telemetry_subject_prefix: &str,
        heartbeat_subject_prefix: &str,
        tenant_id: &str,
    ) -> Result<Self, async_nats::ConnectError> {
        let client = async_nats::connect(nats_url).await?;
        Ok(Self {
            client,
            telemetry_subject_prefix: telemetry_subject_prefix.to_string(),
            heartbeat_subject_prefix: heartbeat_subject_prefix.to_string(),
            tenant_id: tenant_id.to_string(),
        })
    }

    // Subject layout is telemetry.raw.<tenant>.<agent_id> for the current raw transport path.
    pub async fn publish_telemetry(
        &self,
        agent_id: &str,
        payload: Vec<u8>,
    ) -> Result<(), async_nats::PublishError> {
        let subject = format!(
            "{}.{}.{}",
            self.telemetry_subject_prefix,
            self.tenant_id,
            agent_id
        );
        self.client.publish(subject, payload.into()).await
    }

    // Here the heartbeats use a separate subject family so control-plane can subscribe to host liveness
    // all heartbeats live under the heartbeat.*
    pub async fn publish_heartbeat(
        &self,
        agent_id: &str,
        payload: Vec<u8>,
    ) -> Result<(), async_nats::PublishError> {
        let subject = format!(
            "{}.{}.{}",
            self.heartbeat_subject_prefix,
            self.tenant_id,
            agent_id
        );
        self.client.publish(subject, payload.into()).await
    }
}
