package natsx

import (
	"context"
	"fmt"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// I will write the stream definitions here so the every service has the same config
// heartbeats is still on core nats

type StreamDef struct {
	Name     string
	Subjects []string
	MaxAge   time.Duration
}

var (
	TelemetryRawStream = StreamDef{
		Name:     "TELEMETRY_RAW",
		Subjects: []string{"telemetry.raw.>"},
		MaxAge:   24 * time.Hour,
	}

	TelemetryCanonicalStream = StreamDef{
		Name:     "TELEMETRY_CANONICAL",
		Subjects: []string{"telemetry.accepted.>"},
		MaxAge:   24 * time.Hour,
	}

	AlertsStream = StreamDef{
		Name:     "ALERTS",
		Subjects: []string{"alerts.>"},
		MaxAge:   7 * 24 * time.Hour,
	}
)

func JetStream(nc *nats.Conn) (jetstream.JetStream, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("create jetstream context: %w", err)
	}

	return js, nil
}

// first one of run this creates this
func EnsureStream(ctx context.Context, js jetstream.JetStream, def StreamDef) (jetstream.Stream, error) {
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       def.Name,
		Subjects:   def.Subjects,
		Storage:    jetstream.FileStorage,
		MaxAge:     def.MaxAge,
		Duplicates: 2 * time.Minute, // Nats-Msg-Id dedup window
	})
	if err != nil {
		return nil, fmt.Errorf("ensure stream %s: %w", def.Name, err)
	}

	return stream, nil
}

// gives service a named durable consumer with explicit acks, multi instance with same name share same work
func EnsureDurableConsumer(ctx context.Context, stream jetstream.Stream, durable string) (jetstream.Consumer, error) {
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:    durable,
		AckPolicy:  jetstream.AckExplicitPolicy,
		AckWait:    30 * time.Second,
		MaxDeliver: 5, // after this many failed redeliveries the message is dropped
	})
	if err != nil {
		return nil, fmt.Errorf("ensure consumer %s: %w", durable, err)
	}

	return consumer, nil
}
