//! The OpenAPI 3.1 document.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use syn::{GenericArgument, PathArguments, Type};

use crate::scan::{FnInfo, RouteDef, Scan};
use crate::schema::SchemaGen;

/// One route as the router really serves it.
#[derive(Debug, Clone)]
pub struct Served {
    /// Absolute path in OpenAPI syntax (`/api/vpn/peers/{id}`).
    pub path: String,
    pub method: String,
    pub file: String,
    pub handler: String,
    pub is_closure: bool,
    pub route: RouteDef,
    pub handler_ref: crate::scan::HandlerRef,
}

/// Prefix a route's own path gets, from where it is registered.
fn scope(r: &RouteDef) -> Result<&'static str, String> {
    let f = r.file.as_str();
    let n = r.fn_name.as_str();
    if f == "routes/mod.rs" {
        return match n {
            "build_router" => Ok(""),
            "api_routes" => Ok("/api"),
            _ => Err(format!("{f}::{n}: unknown router function")),
        };
    }
    if f.starts_with("routes/api/") {
        return Ok(if n.contains("pages") { "" } else { "/api" });
    }
    if f == "routes/legal.rs" && n.contains("pages") {
        return Ok("");
    }
    Err(format!("{f}::{n}: route registered in an unknown place"))
}

pub fn openapi_path(p: &str) -> String {
    p.split('/')
        .map(|s| {
            if let Some(n) = s.strip_prefix(':').or_else(|| s.strip_prefix('*')) {
                format!("{{{n}}}")
            } else {
                s.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Every (method, absolute path) the sources register, one entry per pair; the entry with a real
/// handler wins over a stub closure registered for the build without the feature.
pub fn served_routes(scan: &Scan) -> Result<Vec<Served>, String> {
    let mut map: BTreeMap<(String, String), Served> = BTreeMap::new();
    // `any(stub)` (the build without a feature answers every method with "not built") only
    // stands for the methods nothing else serves on that path.
    let mut anys: Vec<(String, RouteDef, crate::scan::HandlerRef)> = Vec::new();
    for r in &scan.routes {
        let pre = scope(r)?;
        let path = openapi_path(&format!("{pre}{}", r.path));
        for (m, h) in &r.methods {
            if m == "any" {
                anys.push((path.clone(), r.clone(), h.clone()));
                continue;
            }
            let s = Served {
                path: path.clone(),
                method: m.clone(),
                file: r.file.clone(),
                handler: h.name.clone(),
                is_closure: h.name.starts_with('<'),
                route: r.clone(),
                handler_ref: h.clone(),
            };
            let key = (path.clone(), m.clone());
            match map.get(&key) {
                Some(old) if !old.is_closure || s.is_closure => {}
                _ => {
                    map.insert(key, s);
                }
            }
        }
    }
    for (path, r, h) in anys {
        let has_real = map.iter().any(|((p, _), s)| *p == path && !s.is_closure);
        if has_real {
            continue;
        }
        for m in ["get", "post", "put", "delete", "patch"] {
            map.entry((path.clone(), m.to_string()))
                .or_insert_with(|| Served {
                    path: path.clone(),
                    method: m.to_string(),
                    file: r.file.clone(),
                    handler: h.name.clone(),
                    is_closure: h.name.starts_with('<'),
                    route: r.clone(),
                    handler_ref: h.clone(),
                });
        }
    }
    Ok(map.into_values().collect())
}

pub fn is_api_path(p: &str) -> bool {
    p.starts_with("/api/") || p == "/metrics"
}

fn find_wrapped<'a>(ty: &'a Type, wrapper: &str) -> Option<&'a Type> {
    match ty {
        Type::Path(p) => {
            let seg = p.path.segments.last()?;
            if seg.ident == wrapper {
                if let PathArguments::AngleBracketed(a) = &seg.arguments {
                    for g in &a.args {
                        if let GenericArgument::Type(t) = g {
                            return Some(t);
                        }
                    }
                }
            }
            if let PathArguments::AngleBracketed(a) = &seg.arguments {
                for g in &a.args {
                    if let GenericArgument::Type(t) = g {
                        if let Some(x) = find_wrapped(t, wrapper) {
                            return Some(x);
                        }
                    }
                }
            }
            None
        }
        Type::Tuple(t) => t.elems.iter().find_map(|e| find_wrapped(e, wrapper)),
        Type::Reference(r) => find_wrapped(&r.elem, wrapper),
        Type::Paren(p) => find_wrapped(&p.elem, wrapper),
        _ => None,
    }
}

fn mentions(ty: &Type, ident: &str) -> bool {
    use quote::ToTokens;
    ty.to_token_stream()
        .to_string()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|w| w == ident)
}

/// "GET /api/x -- list the things" -> "List the things": the request line only repeats the
/// method and path the document already has. None = nothing but the request line.
fn summary_of(first: &str) -> Option<String> {
    let t = first.trim();
    if t.starts_with(['`', '{', '[', '(']) {
        return None;
    }
    let starts_with_method = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
        .iter()
        .any(|m| t.starts_with(m) && t[m.len()..].starts_with([' ', '|']));
    if !starts_with_method {
        return Some(first.to_string());
    }
    // drop the method(s) and the path
    let mut rest = t;
    while let Some(c) = rest.chars().next() {
        if c == '/' {
            break;
        }
        rest = &rest[c.len_utf8()..];
    }
    let rest = rest.split_once(char::is_whitespace).map(|(_, r)| r).unwrap_or("");
    let mut r = rest.trim_start();
    loop {
        if let Some(x) = r.strip_prefix('(') {
            // "(re-apply the stored configuration)" is a description, "(admin)" a note: keep both words
            let inner = x.split(')').next().unwrap_or("");
            if inner.split_whitespace().count() >= 3 {
                return Some(cap_first(inner));
            }
            r = x.split_once(')').map(|(_, y)| y).unwrap_or("").trim_start();
            continue;
        }
        for sep in ["-- ", "- ", "— ", ": "] {
            if let Some(x) = r.strip_prefix(sep) {
                r = x.trim_start();
                break;
            }
        }
        break;
    }
    if r.starts_with("->") || r.starts_with('{') || r.starts_with('[') {
        return None;
    }
    let words = r.split_whitespace().filter(|w| w.chars().filter(|c| c.is_alphabetic()).count() >= 3).count();
    (words >= 3).then(|| cap_first(r))
}

fn cap_first(r: &str) -> String {
    let mut c = r.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// One sentence of at most ~140 characters: the first sentence, else cut at a word with an ellipsis.
fn shorten(s: &str) -> String {
    let mut end = s.len();
    for sep in [". ", "; "] {
        if let Some(i) = s.find(sep) {
            end = end.min(i + if sep == ". " { 1 } else { 0 });
        }
    }
    let t = s[..end].trim();
    if t.chars().count() <= 140 {
        return t.to_string();
    }
    let cut: String = t.chars().take(140).collect();
    let cut = cut.rsplit_once(' ').map(|(a, _)| a).unwrap_or(&cut);
    format!("{}…", cut.trim_end_matches([',', ';', ':', '-']))
}

/// "Put ra (dhcp/ra)": the handler's name and where it is, when its doc comment says nothing usable.
fn fallback_summary(handler: &str, path: &str) -> String {
    let tail: Vec<&str> = path
        .trim_start_matches("/api/")
        .split('/')
        .filter(|s| !s.starts_with('{') && !s.is_empty())
        .collect();
    format!("{} ({})", humanize(handler), tail.join("/"))
}

fn humanize(name: &str) -> String {
    let s = name.replace('_', " ");
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn resolve_ref<'a>(v: &'a Value, comps: &'a BTreeMap<String, Value>) -> &'a Value {
    if let Some(r) = v.get("$ref").and_then(|r| r.as_str()) {
        if let Some(n) = r.strip_prefix("#/components/schemas/") {
            if let Some(c) = comps.get(n) {
                return resolve_ref(c, comps);
            }
        }
    }
    v
}

fn properties_of(v: &Value, comps: &BTreeMap<String, Value>) -> Vec<(String, Value, bool, String)> {
    let v = resolve_ref(v, comps);
    let mut out = Vec::new();
    if let Some(all) = v.get("allOf").and_then(|a| a.as_array()) {
        for x in all {
            out.extend(properties_of(x, comps));
        }
    }
    if let Some(p) = v.get("properties").and_then(|p| p.as_object()) {
        let req: Vec<&str> = v
            .get("required")
            .and_then(|r| r.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        for (k, s) in p {
            let desc = s
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            out.push((k.clone(), s.clone(), req.contains(&k.as_str()), desc));
        }
    }
    out
}

pub struct Built {
    pub spec: Value,
    /// (method, path) of every operation in the document.
    pub ops: Vec<(String, String)>,
}

pub fn build(scan: &Scan, version: &str) -> Result<Built, String> {
    let served = served_routes(scan)?;
    let mut gen = SchemaGen::new(scan);
    let mut paths: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut ops = Vec::new();
    let public: &[(&str, &str)] = &[("post", "/api/auth/login"), ("post", "/api/first-run")];

    for s in served.iter().filter(|s| is_api_path(&s.path)) {
        let fi: Option<&FnInfo> = scan.resolve(&s.file, &s.handler_ref);
        let doc = fi.map(|f| f.doc.clone()).unwrap_or_default();
        let ctx_file = fi.map(|f| f.file.as_str()).unwrap_or(&s.file);
        let web_ctx = format!("crates/patronus-web/src/{ctx_file}");
        let doc = if doc.starts_with("This lane's API routes") { String::new() } else { doc };
        let (summary, description) = if doc.is_empty() {
            (
                humanize(if s.is_closure {
                    "inline handler"
                } else {
                    &s.handler
                }),
                String::new(),
            )
        } else {
            let first = doc.split("\n\n").next().unwrap_or("").replace('\n', " ");
            let first = summary_of(first.trim()).unwrap_or_default();
            let sum = shorten(&first);
            if sum.is_empty() {
                (fallback_summary(if s.is_closure { "inline handler" } else { &s.handler }, &s.path), String::new())
            } else {
                (sum, doc.clone())
            }
        };
        let tag_seg = s
            .path
            .trim_start_matches("/api")
            .trim_start_matches('/')
            .split('/')
            .next()
            .filter(|x| !x.is_empty() && !x.starts_with('{'))
            .unwrap_or(if s.path == "/metrics" {
                "metrics"
            } else {
                "api"
            });
        let tag = tag_seg.to_string();

        let mut op = Map::new();
        op.insert("tags".into(), json!([tag]));
        op.insert("summary".into(), json!(summary));
        if !description.is_empty() && description != summary {
            op.insert("description".into(), json!(description));
        }
        let mut idbase = format!("{}{}", s.method, s.path)
            .replace(|c: char| !c.is_alphanumeric(), "_")
            .trim_matches('_')
            .to_string();
        while idbase.contains("__") {
            idbase = idbase.replace("__", "_");
        }
        let n = ids.entry(idbase.clone()).or_insert(0);
        *n += 1;
        op.insert(
            "operationId".into(),
            json!(if *n == 1 {
                idbase
            } else {
                format!("{idbase}_{n}")
            }),
        );
        op.insert(
            "x-patronus-handler".into(),
            json!(format!(
                "{}::{}",
                s.file.trim_end_matches(".rs"),
                if s.is_closure { "(inline)" } else { &s.handler }
            )),
        );

        // path parameters
        let mut params: Vec<Value> = Vec::new();
        let names: Vec<String> = s
            .path
            .split('/')
            .filter_map(|x| x.strip_prefix('{').and_then(|x| x.strip_suffix('}')))
            .map(String::from)
            .collect();
        let path_ty = fi.and_then(|f| f.inputs.iter().find_map(|t| find_wrapped_top(t, "Path")));
        if !names.is_empty() {
            let mut schemas: Vec<Value> = vec![json!({"type": "string"}); names.len()];
            if let Some(t) = path_ty {
                match t {
                    Type::Tuple(tt) => {
                        for (i, e) in tt.elems.iter().enumerate().take(names.len()) {
                            schemas[i] = gen.type_schema(e, &web_ctx);
                        }
                    }
                    t if names.len() == 1 => {
                        let sc = gen.type_schema(t, &web_ctx);
                        if sc.get("$ref").is_none() {
                            schemas[0] = sc;
                        }
                    }
                    t => {
                        let sc = gen.type_schema(t, &web_ctx);
                        let props = properties_of(&sc, &gen.components);
                        for (i, nm) in names.iter().enumerate() {
                            if let Some((_, p, _, _)) = props.iter().find(|(k, ..)| k == nm) {
                                schemas[i] = p.clone();
                            }
                        }
                    }
                }
            }
            for (nm, sc) in names.iter().zip(schemas) {
                params.push(json!({"name": nm, "in": "path", "required": true, "schema": sc}));
            }
        }
        // query
        if let Some(q) = fi.and_then(|f| f.inputs.iter().find_map(|t| find_wrapped_top(t, "Query")))
        {
            let sc = gen.type_schema(q, &web_ctx);
            for (k, p, req, desc) in properties_of(&sc, &gen.components) {
                let mut o = json!({"name": k, "in": "query", "required": req, "schema": p});
                if !desc.is_empty() {
                    o["description"] = json!(desc);
                }
                params.push(o);
            }
        }
        if !params.is_empty() {
            op.insert("parameters".into(), json!(params));
        }
        // body
        if let Some(f) = fi {
            if let Some(b) = f.inputs.iter().find_map(|t| find_wrapped_top(t, "Json")) {
                let sc = gen.type_schema(b, &web_ctx);
                op.insert(
                    "requestBody".into(),
                    json!({"required": true, "content": {"application/json": {"schema": sc}}}),
                );
            } else if let Some(b) = f.inputs.iter().find_map(|t| find_wrapped_top(t, "Form")) {
                let sc = gen.type_schema(b, &web_ctx);
                op.insert(
                    "requestBody".into(),
                    json!({"required": true, "content": {"application/x-www-form-urlencoded": {"schema": sc}}}),
                );
            } else if f.inputs.iter().any(|t| mentions(t, "Multipart")) {
                op.insert(
                    "requestBody".into(),
                    json!({"required": true, "content": {"multipart/form-data": {"schema": {"type": "object"}}}}),
                );
            } else if f.inputs.iter().any(|t| mentions(t, "Bytes")) {
                op.insert(
                    "requestBody".into(),
                    json!({"required": true, "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}),
                );
            }
        }
        // responses
        let mut responses = Map::new();
        let mut ok = json!({"description": "Success"});
        if let Some(f) = fi {
            let json_ty = f.output.as_ref().and_then(|t| find_wrapped(t, "Json"));
            if let Some(t) = json_ty {
                let sc = gen.type_schema(t, &web_ctx);
                ok["content"] = json!({"application/json": {"schema": sc}});
            } else if f.output.as_ref().is_some_and(|t| mentions(t, "Html"))
                || (f.body_idents.contains("Html") && !f.body_idents.contains("Json"))
            {
                ok["content"] = json!({"text/html": {"schema": {"type": "string"}}});
            } else if f.body_idents.contains("Json") {
                ok["content"] = json!({"application/json": {"schema": {}}});
            }
        }
        if s.path == "/metrics" {
            ok["content"] = json!({"text/plain": {"schema": {"type": "string"}}});
        }
        responses.insert("200".into(), ok);
        responses.insert(
            "default".into(),
            json!({"description": "Error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}}),
        );
        responses.insert(
            "401".into(),
            json!({"$ref": "#/components/responses/Unauthorized"}),
        );
        responses.insert(
            "403".into(),
            json!({"$ref": "#/components/responses/Forbidden"}),
        );
        op.insert("responses".into(), Value::Object(responses));
        if public.iter().any(|(m, p)| *m == s.method && *p == s.path) {
            op.insert("security".into(), json!([]));
        }
        let excepted = scan
            .people_only
            .iter()
            .any(|p| p.strip_prefix('!') == Some(s.path.as_str()));
        if !excepted
            && scan
                .people_only
                .iter()
                .any(|p| !p.starts_with('!') && s.path.starts_with(p.as_str()))
        {
            op.insert("x-api-keys-allowed".into(), json!(false));
        }
        paths
            .entry(s.path.clone())
            .or_default()
            .insert(s.method.clone(), Value::Object(op));
        ops.push((s.method.clone(), s.path.clone()));
    }

    let mut comps = Map::new();
    for (k, v) in &gen.components {
        comps.insert(k.clone(), v.clone());
    }
    comps.insert(
        "ApiError".into(),
        json!({"type": "object", "properties": {"error": {"type": "string", "description": "Human-readable message, in the language of the request (Accept-Language or the account's language)."}}, "required": ["error"]}),
    );
    let mut tags: Vec<String> = paths
        .values()
        .flat_map(|m| m.values())
        .filter_map(|o| o["tags"][0].as_str().map(String::from))
        .collect();
    tags.sort();
    tags.dedup();
    let spec = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Patronus API",
            "version": version,
            "summary": "Management API of the Patronus router and firewall",
            "description": "Everything the web UI does goes through this API. Authenticate with the session cookie of a signed-in browser, or with an API key (`Authorization: Bearer <key>` or `X-API-Key`), created under System > API keys. Calls that change configuration need an account or key whose role may modify it (read-only roles get 403). Operations marked `x-api-keys-allowed: false` are for people only. Error bodies are `{\"error\": \"...\"}`, translated into the request language.",
            "license": {"name": "GPL-3.0-or-later", "identifier": "GPL-3.0-or-later"}
        },
        "servers": [{"url": "/", "description": "This router"}],
        "tags": tags.iter().map(|t| json!({"name": t})).collect::<Vec<_>>(),
        "security": [{"cookieAuth": []}, {"bearerAuth": []}, {"apiKeyHeader": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "session_id"},
                "bearerAuth": {"type": "http", "scheme": "bearer"},
                "apiKeyHeader": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
            },
            "responses": {
                "Unauthorized": {"description": "No valid session or API key", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}},
                "Forbidden": {"description": "The role may not do this", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}}
            },
            "schemas": comps
        }
    });
    Ok(Built { spec, ops })
}

/// `Json<T>` / `Path<T>` / ... exactly at the top of an argument type.
fn find_wrapped_top<'a>(ty: &'a Type, wrapper: &str) -> Option<&'a Type> {
    if let Type::Path(p) = ty {
        let seg = p.path.segments.last()?;
        if seg.ident == wrapper {
            if let PathArguments::AngleBracketed(a) = &seg.arguments {
                for g in &a.args {
                    if let GenericArgument::Type(t) = g {
                        return Some(t);
                    }
                }
            }
        }
    }
    None
}
