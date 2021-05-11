package config

import "errors"

// Config is the rrrouter server mode configuration structure
type Config struct {
	MappingURL           string   `help:"URL to remotely stored mapping" group:"mappingsource" xor:"mappingsource" env:"MAPPING_URL"`
	MappingFile          string   `type:"existingfile" help:"Path to local mapping" group:"mappingsource" xor:"mappingsource" env:"MAPPING_FILE"`
	MappingCheckInterval int      `help:"Config check interval in seconds" default:"0" env:"MAPPING_CHECK_INTERVAL"`
	AdminName            string   `help:"Name of the admin account, used for HTTP Basic Auth for management commands" group:"admin" env:"ADMIN_NAME"`
	AdminPass            string   `help:"Password of the admin account" group:"admin" env:"ADMIN_PASS"`
	Port                 int      `kong:"help='Port to use for HTTP',env='PORT',required"`
	RoutingSecrets       []string `help:"List of strings containing known Richie-Routing-Secret values. The first one is used for new internal requests" placeholder:"secret,oldsecret" env:"ROUTING_SECRETS"`
	RetryTimes           []int    `help:"List of integers representing milliseconds to sleep if connection to target fails." default:"10,50,100,200,400" env:"RETRY_TIMES"`
	GZipLevel            int      `help:"Gzip compression level: 1-9." default:"1" env:"GZIP_LEVEL"`
	BrotliLevel          int      `help:"Brotli compression level: 0-11." default:"0" env:"BROTLI_LEVEL"`
	TLSCertPath          string   `kong:"help='Path to TLS certificate file',env='TLS_CERT_PATH',optional"`
	TLSKeyPath           string   `kong:"help='Path to private key file for the TLS certificate',env='TLS_KEY_PATH',optional"`
}

func (c *Config) TLSConfigIsValid() (bool, error) {
	if len(c.TLSCertPath) > 0 && len(c.TLSKeyPath) > 0 {
		return true, nil
	} else if len(c.TLSCertPath) > 0 && len(c.TLSKeyPath) == 0 {
		return false, errors.New("TLS certificate path is configured but path to key is missing")
	} else if len(c.TLSKeyPath) > 0 && len(c.TLSCertPath) == 0 {
		return false, errors.New("TLS key path is configured but path to certificate is missing")
	}

	return false, nil
}
