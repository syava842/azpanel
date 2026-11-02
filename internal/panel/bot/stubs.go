package bot

import "context"

// notifyLoop и scheduleLoop наполняются в следующем коммите.
func (b *Bot) notifyLoop(ctx context.Context)   { <-ctx.Done() }
func (b *Bot) scheduleLoop(ctx context.Context) { <-ctx.Done() }
