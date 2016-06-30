// Copyright (C) 2016 Antoine Tenart <antoine.tenart@ack.tf>

package acl

import (
	"net/http"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type ACL struct {
	Next	httpserver.Handler
}

func (self ACL) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	return self.Next.ServeHTTP(w, r)
}

func setup(c *caddy.Controller) error {
	// create a new Caddy middleware
	mw := func(next httpserver.Handler) httpserver.Handler {
		return &ACL{
			Next: next,
		}
	}

	// register the new Caddy middleware
	cfg := httpserver.GetConfig(c)
	cfg.AddMiddleware(mw)

	return nil
}

func init() {
	caddy.RegisterPlugin("acl", caddy.Plugin{
		ServerType:	"http",
		Action:		setup,
	})
}
