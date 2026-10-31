# Changelog

## [0.5.1](https://github.com/andrewheberle/git-credential-oauth-generic/compare/v0.5.0...v0.5.1) (2026-10-31)


### Bug Fixes

* **release:** handle immutable release process ([#63](https://github.com/andrewheberle/git-credential-oauth-generic/issues/63)) ([849c17c](https://github.com/andrewheberle/git-credential-oauth-generic/commit/849c17cc5b58c26eaeadb842efaaaedfadf03b3e))

## [0.5.0](https://github.com/andrewheberle/git-credential-oauth-generic/compare/v0.4.1...v0.5.0) (2026-10-31)


### Features

* follow the resource_metadata hint from WWW-Authenticate ([#61](https://github.com/andrewheberle/git-credential-oauth-generic/issues/61)) ([b307db5](https://github.com/andrewheberle/git-credential-oauth-generic/commit/b307db5c35ad31f784d42d00addbec6b5198da21))
* refresh with the token Git passes back in --nopersist mode ([#56](https://github.com/andrewheberle/git-credential-oauth-generic/issues/56)) ([4b4064c](https://github.com/andrewheberle/git-credential-oauth-generic/commit/4b4064cc1e80c6836e680091075783ba7eb9037f))


### Bug Fixes

* **deps:** update module github.com/andrewheberle/simplecommand to v0.8.0 ([#40](https://github.com/andrewheberle/git-credential-oauth-generic/issues/40)) ([081a386](https://github.com/andrewheberle/git-credential-oauth-generic/commit/081a386fd308fee81b9bd0abfbaf503eb1dfd5ae))
* **deps:** update module golang.org/x/oauth2 to v0.37.0 ([#47](https://github.com/andrewheberle/git-credential-oauth-generic/issues/47)) ([48f6f54](https://github.com/andrewheberle/git-credential-oauth-generic/commit/48f6f546c147ff35b18b696f93de14bb15fb38df))
* move the browser sign-in into an authorize package ([#52](https://github.com/andrewheberle/git-credential-oauth-generic/issues/52)) ([42dc8a0](https://github.com/andrewheberle/git-credential-oauth-generic/commit/42dc8a073632ef735a973e7eb7f74d0ca654e18c))
* report OAuth discovery failures instead of declining silently ([#58](https://github.com/andrewheberle/git-credential-oauth-generic/issues/58)) ([acc9741](https://github.com/andrewheberle/git-credential-oauth-generic/commit/acc97417578c6523e688ece48c6da4412c841c2c))
* send resource on refresh and keep the refresh token on transient failures ([#60](https://github.com/andrewheberle/git-credential-oauth-generic/issues/60)) ([6ab28f4](https://github.com/andrewheberle/git-credential-oauth-generic/commit/6ab28f45a130efffe65d5dfe81be5097950d590d))
* stop re-registering the OAuth client when the keyring is unavailable ([#57](https://github.com/andrewheberle/git-credential-oauth-generic/issues/57)) ([4099f26](https://github.com/andrewheberle/git-credential-oauth-generic/commit/4099f267fb0d90b24a9b9f5756418ef6b30cc044))
* validate Git credential requests before starting sign-in ([#54](https://github.com/andrewheberle/git-credential-oauth-generic/issues/54)) ([c98e62c](https://github.com/andrewheberle/git-credential-oauth-generic/commit/c98e62caf1ed459a5d4d12394a082859189d58e7))


### Performance Improvements

* skip OAuth discovery when a cached token is valid ([#49](https://github.com/andrewheberle/git-credential-oauth-generic/issues/49)) ([fe3225d](https://github.com/andrewheberle/git-credential-oauth-generic/commit/fe3225d7e6e1eca62f7ddd6e647eed300ef60421))
