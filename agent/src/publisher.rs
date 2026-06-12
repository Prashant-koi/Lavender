use async_nats::jetstream;

pub struct Publisher {
    client: async_nats::Client,
    jetstream: jetstream::Context,
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
        let jetstream = jetstream::new(client.clone());
        Ok(Self {
            client,
            jetstream,
            telemetry_subject_prefix: telemetry_subject_prefix.to_string(),
            heartbeat_subject_prefix: heartbeat_subject_prefix.to_string(),
            tenant_id: tenant_id.to_string(),
        })
    }

    // Subject layout is telemetry.raw.<tenant>.<agent_id> for the current raw transport path.
    // Telemetry goes through jetstream so we get an ack that the broker persisted it
    // and event_id also woks as the msg id so retries can't don't have the same event twice
    // agent just publishes into the stream created by the backend services
    pub async fn publish_telemetry(
        &self,
        agent_id: &str,
        event_id: &str,
        payload: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let subject = format!(
            "{}.{}.{}",
            self.telemetry_subject_prefix,
            self.tenant_id,
            agent_id
        );

        let ack_future = self
            .jetstream
            .send_publish(
                subject,
                jetstream::context::Publish::build()
                    .message_id(event_id)
                    .payload(payload.into()),
            )
            .await?;

        // first await sends, second await waits for the broker to confirm persistence
        ack_future.await?;
        Ok(())
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
