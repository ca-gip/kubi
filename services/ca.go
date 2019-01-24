package services

import (
	"intomy.land/kubi/utils"
	"io"
	"net/http"
)

func CA(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, utils.Config.KubeCaText)
}
