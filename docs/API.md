# The Patronus API

Everything the web UI does goes through a JSON API under `/api`. It is described by an
OpenAPI 3.1 document that is generated from the router's own source, so it cannot drift.

- **On a running box**: `https://ROUTER/api/docs` (reference page: search, parameters, request and
  response shapes) and `https://ROUTER/api/openapi.json` (the document). Both need a signed-in
  session or an API key, like every other `/api` call.
- **In the repository**: [`docs/openapi.json`](openapi.json) (the same document, pretty-printed) and
  [`docs/API-COVERAGE.md`](API-COVERAGE.md) (which UI page uses which API paths, and which pages
  have none).

The document describes the whole API. A build or a router tier that leaves a feature out answers that
feature's routes with an explanation (501, or 409 on an access point); `GET /api/features` lists what
the running build has.

## Calling it

```
curl -sk -H "Authorization: Bearer $KEY" https://ROUTER/api/firewall/rules
curl -sk -H "X-API-Key: $KEY" https://ROUTER/api/status
```

A key is created under System > API keys; it carries a role (read-only keys get 403 on anything
that changes configuration). Operations marked `x-api-keys-allowed: false` in the document (accounts,
keys, groups, factory reset, backup targets, authentication servers) are for people only. Errors are
`{"error": "..."}`; the message is in the request's language (`Accept-Language`, or the signed-in
account's own choice, see [I18N.md](I18N.md)). Handlers written for the catalog also return a stable
`"code"`.

## How the document is made

`cargo run -p patronus-openapi` reads `crates/patronus-web/src` with `syn`:

- every `.route("/path", get(h).post(h2))` call is an operation (the path prefix follows from where the
  router function is mounted: `/api` for the API routers, none for pages);
- the handler's doc comment is the summary and description, its `Path<T>`, `Query<T>`,
  `Json<T>` / `Form<T>` arguments and its `Json<T>` return type give parameters, request body and
  response, and the serde types (any crate of the workspace) become the JSON schemas, honouring
  `rename`, `rename_all`, `default`, `skip`, `flatten`, `tag`/`content` and `untagged`;
- the result is written to `docs/openapi.json` and to `crates/patronus-web/openapi/openapi.json`
  (compact, compiled into `patronus-web`), plus `docs/API-COVERAGE.md`.

Handlers that return a bare `Response` have an untyped JSON answer in the document: give such a
handler a `Json<T>` return type (or a `///` comment naming the shape) and rerun the generator.

## What CI checks

- `patronus-openapi` tests: the committed files equal what the generator produces; every route the
  sources register is in the document and the document has nothing the sources do not serve; every
  `$ref` resolves, operation ids are unique, every path parameter is declared; every UI page either
  calls the API or is listed with a reason in `crates/patronus-openapi/page-api-exempt.txt`.
- `patronus-web` test `every_route_of_the_router_is_in_the_openapi_document`: the same comparison
  against the router that is actually built (read from axum's route table), so a route registered in
  a way the scanner does not understand still fails the build.
- `ci/netlab/lane-w-i18n-ui.sh` drives `/api/docs` in Firefox; the accessibility gate covers the page
  at 1280 and 390 px in both colour schemes.
- The embedded images' QEMU gates fetch the document and the page from the booted router.

## Adding an API route

Add the route and the handler as usual (one `.merge(...)` line, see AGENTS.md), then run
`cargo run -p patronus-openapi` and commit the three generated files. Write a `///` comment on the
handler (first sentence = the summary) and return `Json<T>` with a `Serialize` type where you can.
New error messages go through `i18n::api_error` with a catalog key.
