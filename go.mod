module github.com/krombel/traefik_openid

go 1.19

require (
	github.com/coreos/go-oidc/v3 v3.9.0
	golang.org/x/oauth2 v0.15.0
)

require (
	github.com/go-jose/go-jose/v3 v3.0.1 // indirect
	golang.org/x/crypto v0.17.0 // indirect
)

replace golang.org/x/oauth2 v0.15.0 => gitea.krombel.de/krombel/oauth2 v0.15.0-1
