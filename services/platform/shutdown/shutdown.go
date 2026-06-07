package shutdown

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func Context() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
