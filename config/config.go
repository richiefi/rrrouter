package config

// Config is the rrrouter server mode configuration structure
type Config struct {
	MappingURL     string   `help:"URL to remotely stored mapping" group:"mappingsource" xor:"mappingsource" env:"MAPPING_URL"`
	MappingFile    string   `type:"existingfile" help:"Path to local mapping" group:"mappingsource" xor:"mappingsource" env:"MAPPING_FILE"`
	AdminName      string   `help:"Name of the admin account, used for HTTP Basic Auth for management commands" group:"admin" env:"ADMIN_NAME"`
	AdminPass      string   `help:"Password of the admin account" group:"admin" env:"ADMIN_PASS"`
	Port           int      `kong:"help='Port to use for HTTP',env='PORT',required"`
	RoutingSecrets []string `help:"List of strings containing known Richie-Routing-Secret values. The first one is used for new internal requests" placeholder:"secret,oldsecret" env:"ROUTING_SECRETS"`
	RetryTimes     []int    `help:"List of integers representing milliseconds to sleep if connection to target fails." default:"10,50,100,200,400" env:"RETRY_TIMES"`
	GZipLevel      int      `help:"Gzip compression level: 1-9." default:"1" env:"GZIP_LEVEL"`
	BrotliLevel    int      `help:"Brotli compression level: 0-11." default:"0" env:"BROTLI_LEVEL"`
}
