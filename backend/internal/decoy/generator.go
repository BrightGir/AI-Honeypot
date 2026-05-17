package decoy

import (
	"context"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
)

// Generator is implemented by any LLM client that can produce decoy responses.
type Generator interface {
	GenerateDecoyResponse(ctx context.Context, persona *model.Persona, userMessage string) (string, error)
}
