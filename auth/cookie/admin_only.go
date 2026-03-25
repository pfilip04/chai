package cookie

import (
	"net/http"

	"github.com/pfilip04/chai/global/enums"
	"github.com/pfilip04/chai/global/errs"
)

func (c *CookieAuth) AdminOnly(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		_, err := c.AdminAuthorize(r)

		if err != nil {

			errs.WriteError(w, enums.AdminOnly, err, "Admin: This request is admin-only", errs.ForbiddenError)
			return
		}

		next.ServeHTTP(w, r)
	})
}
