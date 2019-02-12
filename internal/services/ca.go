package services

import (
	"github.com/ca-gip/kubi/internal/utils"
	"io"
	"net/http"
)

func CA(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, utils.Config.KubeCaText)
}
