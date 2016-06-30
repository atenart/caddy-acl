// Copyright (C) 2016 Antoine Tenart <antoine.tenart@ack.tf>

package acl

import (
	"net"
	"net/http"
	"strconv"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type ACL struct {
	Next	httpserver.Handler
	Config	[]ACLBlockConfig
}

// describe one acl{} configuration block
type ACLBlockConfig struct {
	Paths	[]string
	Allow	[]*net.IPNet
	Deny	[]*net.IPNet
	Status	int
}

func parsePrefix(c *caddy.Controller) (*net.IPNet, error) {
	if !c.NextArg() {
		return nil, c.ArgErr()
	}

	_, ret, err := net.ParseCIDR(c.Val())
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func parseConfigurationBlock(c *caddy.Controller) (ACLBlockConfig, error) {
	var cfg ACLBlockConfig

	// get acl{} block first arguments (base paths)
	// TODO: sort the paths: most specific first
	cfg.Paths = c.RemainingArgs()
	if len(cfg.Paths) == 0 {
		return cfg, c.ArgErr()
	}

	// navigate through statements in an acl{} block
	for c.NextBlock() {
		val := c.Val()

		switch val {
		case "allow":
			rule, err := parsePrefix(c)
			if err != nil {
				return cfg, err
			}

			cfg.Allow = append(cfg.Allow, rule)
		case "deny":
			rule, err := parsePrefix(c)
			if err != nil {
				return cfg, err
			}

			cfg.Deny = append(cfg.Deny, rule)
		case "status":
			if !c.NextArg() {
				return cfg, c.ArgErr()
			}

			status, _ := strconv.Atoi(c.Val())
			if http.StatusText(status) == "" {
				// invalid HTTP status code
				return cfg, c.Err("acl: invalid status code")
			}

			cfg.Status = status
		}
	}

	return cfg, nil
}

func parseConfiguration(c *caddy.Controller) ([]ACLBlockConfig, error) {
	var config []ACLBlockConfig

	// navigate through the acl{} blocks
	for c.Next() {
		blockConf, err := parseConfigurationBlock(c)
		if err != nil {
			return config, err
		}

		config = append(config, blockConf)
	}

	return config, nil
}

func (self ACL) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	return self.Next.ServeHTTP(w, r)
}

func setup(c *caddy.Controller) error {
	// parse Caddyfile for acl configuration statements
	aclConf, err := parseConfiguration(c)
	if err != nil {
		return err
	}

	// create a new Caddy middleware
	mw := func(next httpserver.Handler) httpserver.Handler {
		return &ACL{
			Next:	next,
			Config:	aclConf,
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
