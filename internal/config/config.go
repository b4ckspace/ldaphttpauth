package config

import (
	"fmt"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

type (
	Config struct {
		Realm           string `default:"Authentication"`
		LdapHost        string `required:"true"`
		LdapBind        string `required:"true"`
		LdapTLSHostname string
		HttpBind        string `default:":8042"`
	}
)

func ParseConfig() (c *Config, err error) {
	err = envconfig.Process("", &c)
	if err != nil {
		return nil, fmt.Errorf("unable to load config: %s", err)
	}
	if c.LdapTLSHostname == "" {
		if strings.Contains(c.LdapHost, ":") {
			c.LdapTLSHostname = c.LdapHost[:strings.Index(c.LdapHost, ":")]
		} else {
			c.LdapTLSHostname = c.LdapHost
		}
	}
	return c, nil
}
