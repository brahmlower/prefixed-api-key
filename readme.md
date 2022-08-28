
# A Rust implementation of Prefixed API Key

This library is a Rust implementation of the [Prefixed API Key](https://github.com/seamapi/prefixed-api-key) typescript library. Though its interface differs slightly from the typescript version, this library provides the same set of features and functionality as the typescript version.

⚠️ This library is still a work in progress.

## Prefixed API Key (Seam-style)

> Example key: `mycompany_BRTRKFsL_51FwqftsmMDHHbJAMEXXHCgG`

> [See discussion on Hacker News](https://news.ycombinator.com/item?id=31333933#31336542)

Seam-style API Keys have many advantages:

- Double clicking the api key selects the entire api key
- The alphabet is standard across languages thanks [to the base58 RFC](https://datatracker.ietf.org/doc/html/draft-msporny-base58) and its usage in cryptocurrencies
- They are shorter than hex and base32 api keys
- They have prefixes [allowing secret scanning by github](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
- They have a hashed component so the server doesn't need to store the api key (reducing attack surface)
- They have unhashed short tokens which can be mutually used by the server and key bearer/customer to identify the api key
- They default to roughly the same number of entropy bits as UUIDv4

### The Format

Seam-style api keys look like this:

```
mycompany_BRTRKFsL_51FwqftsmMDHHbJAMEXXHCgG
```

Let's break down each component of the API key...

```
mycompany ..._...  BRTRKFsL ..._...  51FwqftsmMDHHbJAMEXXHCgG
^                  ^                 ^
Prefix             Short Token       Long Token
```

- The Prefix is used to identify the company or service creating the API Key.
  This is very helpful in secret scanning.
- The Short Token is stored by both the server and the key bearer/customer, it
  can be used to identify an API key in logs or displayed on a customer's
  dashboard. A token can be blocklisted by its short token.
- The Long Token is how we authenticate this key. The long token is never stored
  on the server, but a hash of it is stored on the server. When we receive an
  incoming request, we search our database for `short_token` and `hash(long_token)`.

## Getting Started

code examples coming tomorrow 😴
