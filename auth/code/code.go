package code

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (vc *VerificationCode) VerifyCode(w http.ResponseWriter, r *http.Request) {

	code := r.FormValue("6-DIGIT-CODE")

	mfaType := chi.URLParam(r, "mfa_type")

	id, err := uuid.Parse(r.URL.Query().Get("id"))

	if err != nil {

		http.Error(w, "Couldn't get link id", http.StatusBadRequest)
		return
	}

	verified, err := MfaVerify(DbQuery{
		Db:           vc.DB,
		queryTimeout: vc.queryTimeout,
		ctx:          r.Context(),
	}, Credentials{
		mfaId:   id,
		code:    code,
		apiName: mfaType,
	})

	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !verified {

		http.Error(w, "Verification code missmatch", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "Code verification successful")
}
