package services

import (
	"io"
	"net/http"

	"github.com/ca-gip/kubi/internal/utils"
)

func CA(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, err := io.WriteString(w, utils.Config.KubeCaText)

	if err != nil {
		utils.Log.Error().Err(err).Msg("Error writing to response")
	}
}
