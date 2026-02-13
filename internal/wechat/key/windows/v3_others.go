//go:build !windows

package windows

import (
	"context"

	"github.com/DanielMao1/chatlog/internal/wechat/model"
)

func (e *V3Extractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	return "", "", nil
}
