# git-credential-oauth-generic

A Git credential helper that obtains OAuth access tokens for a Git host by discovering its authorization server through standard RFCs, and hands them to Git as Bearer credentials.

## Language

**Resource URL**:
`https://<host>` for the Git host being accessed; the key under which everything for that host is cached and configured.
_Avoid_: host URL, server URL

**Credential request**:
The attributes Git sends a credential helper on stdin (protocol, host, announced capabilities). The helper only answers requests for `https` with a host, declining all others so Git tries the next helper.
_Avoid_: input, pairs, git input

**Token cache**:
The per-Resource URL store of the access token, refresh token and expiry that the helper has obtained, kept so later Git operations can reuse or refresh them. It never holds the client secret; with `--nopersist` it holds only the refresh token Git passed back in the Credential request, and stores nothing.
_Avoid_: keychain, token store, credential store

**Registered client**:
The OAuth client this helper is known as to an authorization server: a client ID and the redirect URI it was registered with (in Git config) and, if one was issued, a client secret (in the OS keyring, keyed by client ID). It belongs to client registration, not to the Token cache, and outlives any token. A client ID set by hand has no recorded redirect URI and is never replaced.
_Avoid_: app, client credentials

**Credential acquisition**:
Turning a Resource URL into an access token Git can use, preferring in order: a valid token from the Token cache, a refresh, then the Authorizer (registering a client first if none is registered).
_Avoid_: login, auth flow, token fetch

**Authorizer**:
The interactive step of Credential acquisition: the PKCE authorization code flow in the user's browser, with a localhost callback.
_Avoid_: browser login, OAuth dance
