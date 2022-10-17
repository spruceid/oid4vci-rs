# oidc4vci-rs

`oidc4vci-rs` is a library providing types and functions for handling
`OIDC4VCI` protocol parameters and requests/responses.

## Docker

Build image:

```bash
% pwd
/oidc4vci-rs

cd ..
git clone git@github.com:spruceid/ssi.git

# must be run from .. where SSI has been cloned
docker build -f oidc4vci-rs/Dockerfile --progress=plain -t oidc4vci-rs .
```

