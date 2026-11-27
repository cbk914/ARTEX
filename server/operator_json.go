package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

const operatorMutationBodyLimit = 4096

// strictOperatorJSON accepts one small JSON object for a privileged mutation.
func strictOperatorJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeErr(w, http.StatusUnsupportedMediaType, "application/json required")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, operatorMutationBodyLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeOperatorJSONError(w, err)
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			writeErr(w, http.StatusBadRequest, "one JSON object required")
		} else {
			writeOperatorJSONError(w, err)
		}
		return false
	}
	return true
}

func writeOperatorJSONError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
	} else {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
	}
}
