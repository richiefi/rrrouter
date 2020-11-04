# Richie Request Router

Richie Request Router, or `rrrouter`, is a HTTP reverse proxy.

It accepts incoming HTTP requests, chooses the first matching forwarding rule from an ordered ruleset, and proxies the request, performing minimal header rewrites in the process.

## Running with Docker

This repository contains a `Dockerfile` that can be used to build and run rrrouter, also in production. Note that the image only includes the `richie-request-router` binary, not the config utility. To update the config, build rrrouter locally.

In your working copy, you can build the Docker image like this:

```
docker build -t rrrouter .
```

Either the `MAPPING_FILE` or `MAPPING_URL `environment variable is mandatory. A complete invocation example is thus:

```
docker run \
  -e MAPPING_URL=[latest mapping config url] \
  --publish 8080:5000 \
  rrrouter
```

## Building and Running

rrrouter is written in Go. It uses the go module system.

To compile rrrouter, check out the repo and run

```sh
go install ./...
```

rrrouter requires some environment variables to run. To see full list of mandatory and optional variables, run

```sh
richie-request-router --help
```

## Routing Configuration

rrrouter's routing configuration consists of a list of *rules*, each containing an *url pattern*, a *destination* and additional flags.

The configuration can be specified in JSON or YAML and can be fetched from a remote URL (set with the `MAPPING_URL` environment variable) or a local file (using `MAPPING_FILE`).

```json
{
	"rules": [
		{
			"pattern": "app.example.com/config/v1/*",
			"destination": "https://richie-appconfig.herokuapp.com/v1/$1",
			"internal": true
		},
		{
			"pattern": "http://app.example.com/external-customer-1/srv/*",
			"destination": "https://s.external-customer-1.com/$1"
		}
	]
}
```

```yaml
rules:
    - destination: https://richie-appconfig.herokuapp.com/v1/$1
      internal: true
      pattern: app.example.com/config/v1/*
    - destination: https://s.external-customer-1.com/$1
      pattern: http://app.example.com/external-customer-1/srv/*
```

The pattern can include asterisks (*) as wildcards. The destinations can refer to these wildcards with the $1, $2 (etc) notation.

If the pattern doesn't start with `http://` or `https://`, it will match both.

The first matching rule is selected.

You can check the syntax of a routing configuration with the `checkmapping` subcommand:

```sh
richie-request-router checkmapping --url=https://example.com/config.json
richie-request-router checkmapping --file=./config.json
```

A matching route in the configuration for a single query can be searched with the `checkquery` subcommand:

```sh
richie-request-router checkquery --url=https://example.com/config.json --method=GET --query=http://app.example.com/config/v1/example
richie-request-router checkquery --file=./config.json --method=GET --query=http://app.example.com/config/v1/example
```

The outputs of `checkmapping` and `checkquery` contain rule structures for proxy and copy rules. If a rule is present, its representation in output contains flags, matching methods, original URL pattern and destination URL pattern. In the representation, the flags are specified as followed:
- I - the rule is internal (it has `internal` flag)
- E - the rule is external (it has no `internal` flag)
- P - the rule is a proxy rule
- C - the rule is a copy rule
- Example:

  `Rule (I,P) * "app.example.com/config/v1/*" -> "https://richie-appconfig.herokuapp.com/v1/$1"`

  The rule is an internal proxy rule, it matches all the HTTP methods and the beginning of the URL is replaced with the first parts of an application's actual Heroku URL.

## Method Filtering

You can specify that a rule applies to only a subset of HTTP methods. To do this, include a `methods` list in a rule.

```json
{
	"rules": [
		{
			"pattern": "app.example.com/config/v1/*",
			"destination": "https://richie-appconfig.herokuapp.com/v1/$1",
			"internal": true,
			"methods": ["GET", "HEAD"]
		}
	]
}
```

## Response compression

You can specify that a request with Accept-Encoding of either `br` or `gzip` should be fulfilled by rrrouter. For example, if the request specifies `Accept-Encoding: br` and the origin response is `application/json` with no `Content-Encoding` applied, rrrouter will compress it with Brotli and return `Content-Encoding: br`.

Additionally, with a client request with `Accept-Encoding: br`, origin being `Content-Encoding: gzip` the content will be first decompressed and re-compressed with Brotli.

Only plain text types `application/json` and `text/<anything>`, when `Content-Encoding` is missing or `identity` will be compressed with the desired `Accept-Encoding`.

Compression level can be specified with environment variables BROTLI_LEVEL (0-11, defaults to 0) and GZIP_LEVEL (1-9, defaults to 1)

Rules without this field default to not performing any compression.

```yaml
rules:
    - destination: https://richie-appconfig.herokuapp.com/v1/$1
      pattern: app.example.com/config/v1/*
      recompression: true
```

## Traffic Copying

In addition to proxying requests, rrrouter can copy traffic to a host without reporting this to the user.

```json
{
	"rules": [
		{
			"pattern": "app.example.com/config/v1/*",
			"destination": "https://richie-appconfig-staging.herokuapp.com/v1/$1",
			"internal": true,
			"type": "copy_traffic"
		},
		{
			"pattern": "app.example.com/config/v1/*",
			"destination": "https://richie-appconfig.herokuapp.com/v1/$1",
			"internal": true
		}
	]
}
```

With this configuration, in addition to creating a request to `https://richie-appconfig.herokuapp.com/v1/q`, a request to `app.example.com/config/v1/q` is also sent to `https://richie-appconfig-staging.herokuapp.com/v1/q`. The user does not see this; the response from the non-copy target is returned.

A `type` field with value `proxy` is equivalent to a missing `type` field, and means the default behavior.

**A note on memory usage:** rrrouter tries to conserve memory, but it has to read the request body to memory most of the time. There's only one situation where it isn't necessary: it's a POST request (so not retryable because it's not idempotent) and there is only one of  `copy_traffic` and `proxy` rules matching it (because you can't stream to two places without at least some copying and syncing, none of which rrrouter does at the moment.) If you use traffic copying or non-POST methods with endpoints that receive large requests, this can lead to significant memory usage.

## Rule Selection

The mechanism for selecting rules is as follows:

1. Rules are checked in the order they are in the file.
2. If a rule has a `methods` list and it does not include the request method, the rule is skipped.
3. If a rule's pattern matches and its type is `copy_traffic`, it's selected as the copy target. This will not be overridden by later `copy_traffic` matches.
4. If a rule's pattern matches and its type is `proxy`, it's selected as the proxy target and the search is terminated.


## Request and Response Headers

rrrouter forwards all request headers to the destination server. The exception is the Host header, which is rewritten according to destination specified in the rule. This means that the destination server does not need to know the hostnames used by the upstream clients to access the content. It also means that the destination is expected to present a certificate for its own name, rather than the name the client used to perform the request.

Each forwarding destination can be configured as internal or external. Internal destinations are our own microservices. External destinations are other systems, like Amazon S3.

When forwarding requests to *internal* destinations (see the [Routing Configuration](#routing-configuration) section) and the `ROUTING_SECRETS` environment variable is set, rrrouter adds three custom request headers to each request. These are:

- Richie-Originating-IP
- Richie-Request-ID
- Richie-Routing-Secret

As per RFC 6648, no “X-” prefix is used in these names.

**Richie-Originating-IP** is the IP address (either IPv4 or IPv6) of the connecting client. The value can currently be copied from `the CF-Connecting-IP` header added by CloudFlare. The intention is to remove the need to hardcode a CloudFlare-specific header name into downstream microservices implementations while also discouraging the use of the inherently unreliable `X-Forwarded-For` header.

**Richie-Request-ID** is a random UUID assigned by rrrouter for the request. This is intended to allow the correlation of requests within various microservices to a single originating (external) request, for example when analyzing log files.

**Richie-Routing-Secret** is a shared secret known by the rrrouter and downstream microservices. This allows microservices to deny all requests without a valid secret. This makes the rrrouter into a firewall of sorts; without this mechanism, services hosted on public PaaS providers like Heroku are directly accessible by anyone guessing the application endpoint, which can be trivial. More than one valid secret may exist at any given time, but the rrrouter will only ever send the latest one on the list. This is to allow key rotation without the risk of denied requests. These keys are configured with the `ROUTING_SECRETS` environment variable.

When an incoming request contains a valid `Richie-Routing-Secret`, it, along with the `Richie-Originating-IP` and `Richie-Request-ID` headers, are forwarded as-is to the destination. This enables Richie microservices to perform additional requests to other microservices via the rrrouter while retaining the information in the original/external request.

A missing value in one of the other headers is replaced with a new one in incoming requests with a valid `Richie-Routing-Secret` header.

If an incoming request has an invalid `Richie-Routing-Secret` or it's missing but one of the other headers has a value, the request is denied and status code 407 is returned.

## System information

There's an admin endpoint, `/__SYSTEMINFO`, for checking state of the system rrrouter is running on. The endpoint requires that the `ADMIN_NAME` and `ADMIN_PASS` environment variables are set.

The `/__RRROUTER/health` endpoint always returns 200 OK.
