package services

import (
	"intomy.land/kube-ldap/utils"
	"io"
	"net/http"
)

func CA(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, utils.Config.KubeCaText)
}
