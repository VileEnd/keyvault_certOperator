package azure_test

import (
	"context"

	"github.com/VileEnd/keyvault_certOperator/internal/app"
	"github.com/VileEnd/keyvault_certOperator/internal/domain"
)

// testContext aliases context.Context purely to keep the fake server's long
// callback signatures readable in this file.
type testContext = context.Context

type staticSource struct{ bundle *domain.Bundle }

func (s staticSource) Load(context.Context, app.SecretRef) (*domain.Bundle, error) {
	return s.bundle, nil
}
