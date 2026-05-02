pub struct Publisher {
    client: async_nats::Client,
    subject_prefix: String,
    tenant_id: String,
}

impl Publisher {
    // We connect once at startup and reuse the client for all telemetry publishes.
    pub async fn connect(
        nats_url: &str,
        subject_prefix: &str,
        tenant_id: &str,
    ) -> Result<Self, async_nats::ConnectError> {
        let client = async_nats::connect(nats_url).await?;
        Ok(Self {
            client,
            subject_prefix: subject_prefix.to_string(),
            tenant_id: tenant_id.to_string(),
        })
    }

    // Subject layout is telemetry.raw.<tenant>.<agent_id> for the current raw transport path.
    pub async fn publish_telemetry(
        &self,
        agent_id: &str,
        payload: Vec<u8>,
    ) -> Result<(), async_nats::PublishError> {
        let subject = format!("{}.{}.{}", self.subject_prefix, self.tenant_id, agent_id);
        self.client.publish(subject, payload.into()).await
    }
}
