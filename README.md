# OpenID Authentication Plugin

This OpenID authentication plugin is a middleware for Go applications, which manages user authentication using OpenID, an open-source identity and access management solution.

## State:
This is currently broken with upstream dependencies.
This are the relevant issues:
- go-jose: https://github.com/go-jose/go-jose/issues/56 (patched by changes mentioned in linked issue)
- protobuf (a dependency of oauth2) uses "unsafe" dependency which is not possible currently. When trying to import this there is the following error:
```
import "unsafe" error: unable to find source related to: "unsafe"
```
- https://github.com/traefik/traefik/issues/7459 (closed by not fixed) => a patched version is vendored to resolve this issue
- https://github.com/traefik/yaegi/issues/1603 (function overloading does not work) => vendored version of go-oidc patched to not overload UnmarshalJSON
- https://github.com/traefik/yaegi/issues/1502 (go-jose not usable) => Disabled JWT signature check (UNSECURE!!)

## Attribution:

This is mainly a generalization of https://github.com/Gwojda/keycloakopenid to support OpenID Providers including keycloak

## Code Explanation

### Structs

The plugin uses several data structures:

- Config: This struct stores the configuration details of the OpenID instance, such as the URL, client ID, and client secret.
  oidcAuth: This struct is the main component of the plugin, storing the next HTTP handler and the configuration.
- state: This struct stores the URL to which the user should be redirected after successful authentication.

### Main Functions

The plugin has several main functions:

- CreateConfig(): Initializes and returns a new Config struct.
- New(): Creates a new OpenID authentication middleware. It checks the provided configuration and returns an error if the OpenID Provider URL or client ID is not provided.
- ServeHTTP(): This is the main function of the middleware. It checks for an "Authorization" cookie in the request. If the cookie exists and its value starts with "Bearer ", it verifies the token. If the token is valid, it allows the request to proceed. If the token is invalid, it redirects the request to OpenID for authentication. If the cookie does not exist, it checks for an authorization code in the request URL. If the code exists, it exchanges it for a token. If the code does not exist, it redirects the request to the OpenID Provider for authentication.
- exchangeAuthCode(): Exchanges an authorization code for a token.
- redirectToOpenIDProvider(): Redirects the request to the OpenID Provider for authentication.
- verifyToken(): Verifies the validity of a token.

## How it Works

When a request is received, the middleware first checks for an "Authorization" cookie. If it exists and the token inside is valid, the request is allowed to proceed.
If the token is invalid or doesn't exist, the middleware checks for an authorization code in the request URL.
If the authorization code exists, the middleware exchanges it for a token, sets this token as a cookie, and redirects the user to their original location.
If the authorization code doesn't exist, the middleware redirects the user to the OpenID Provider for authentication.
The user is then prompted to enter their credentials on the the OpenID Providers login page. After successful authentication, the OpenID Provider redirects the user back to the application with an authorization code.
The middleware then exchanges this code for a token and the process starts over.
By using this middleware, applications can easily integrate with OpenID Connect for user authentication without having to implement the logic themselves.

## Installation

First, enable the plugins support in your Traefik configuration file (traefik.yml or traefik.toml):

```yaml
experimental:
  plugins:
    traefik_openid:
      moduleName: "github.com/krombel/traefik_openid"
      version: "v0.1.32"
```

Usage
Add the plugin's specific configuration to your Traefik routers:

```yaml
http:
  middlewares:
    my-openid:
      plugin:
        traefik_openid:
          ProviderURL: "my-openid-provider-url.com" # <- base url for well-known lookup - might by my-keycloak.com/realms/world
          ClientID: "<CLIENT_ID"
          ClientSecret: "<CLIENT_SECRET"
```

Alternatively, ClientID and ClientSecret can be read from a file to support Docker Secrets and Kubernetes Secrets:

```yaml
http:
  middlewares:
    my-openid:
      plugin:
        traefik_openid:
          ProviderURL: "https://my-openid-provider-url.com"
          ClientIDFile: "/run/secrets/clientId.txt"
          ClientSecretFile: "/run/secrets/clientSecret.txt"
```

Last but not least, each configuration can be read from environment file to support some Kubernetes configurations:

```yaml
http:
  middlewares:
    my-openid:
      plugin:
        traefik_openid:
          ProviderURLEnv: "MY_OPENID_PROVIDER_URL"
          ClientIDEnv: "MY_CLIENT_ID"
          ClientSecretEnv: "MY_CLIENT_SECRET"
```

This plugin also sets a header with a claim from the OpenID Provider, as it has become reasonably common. Claim name and header name can be modified.
The default claim is <code>preferred_username</code>, the default header name is <code>X-Forwarded-User</code> :

```yaml
http:
  middlewares:
    my-openid:
      plugin:
        traefik_openid:
          ProviderURL: "my-openid-provider-url.com" # <- <- base url for well-known lookup - might by my-keycloak.com/realms/world
          ClientID: "<CLIENT_ID"
          ClientSecret: "<CLIENT_SECRET"
          UserClaimName: "my-uncommon-claim"
          UserHeaderName: "X-Custom-Header"
```
