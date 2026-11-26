//! serde types -> JSON Schema (OpenAPI 3.1 components), read from the source definitions.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Map, Value};
use syn::{Attribute, Expr, Fields, GenericArgument, Lit, PathArguments, Type};

use crate::scan::{doc_of, Scan, TypeDef, TypeItem};

#[derive(Default, Clone)]
struct Serde {
    rename: Option<String>,
    rename_all: Option<String>,
    default: bool,
    skip: bool,
    flatten: bool,
    tag: Option<String>,
    content: Option<String>,
    untagged: bool,
}

fn consume(m: &syn::meta::ParseNestedMeta) -> syn::Result<()> {
    if m.input.peek(syn::Token![=]) {
        let _: Expr = m.value()?.parse()?;
    } else if m.input.peek(syn::token::Paren) {
        m.parse_nested_meta(|n| consume(&n))?;
    }
    Ok(())
}

fn lit_str(m: &syn::meta::ParseNestedMeta) -> syn::Result<String> {
    let e: Expr = m.value()?.parse()?;
    if let Expr::Lit(l) = &e {
        if let Lit::Str(s) = &l.lit {
            return Ok(s.value());
        }
    }
    Ok(String::new())
}

fn serde_attrs(attrs: &[Attribute]) -> Serde {
    let mut s = Serde::default();
    for a in attrs {
        if !a.path().is_ident("serde") {
            continue;
        }
        let _ = a.parse_nested_meta(|m| {
            if m.path.is_ident("rename") {
                if m.input.peek(syn::Token![=]) {
                    s.rename = Some(lit_str(&m)?);
                } else {
                    // rename(serialize = "..", deserialize = "..")
                    m.parse_nested_meta(|n| {
                        if n.path.is_ident("serialize") && s.rename.is_none() {
                            s.rename = Some(lit_str(&n)?);
                        } else {
                            consume(&n)?;
                        }
                        Ok(())
                    })?;
                }
            } else if m.path.is_ident("rename_all") {
                if m.input.peek(syn::Token![=]) {
                    s.rename_all = Some(lit_str(&m)?);
                } else {
                    m.parse_nested_meta(|n| {
                        if n.path.is_ident("serialize") && s.rename_all.is_none() {
                            s.rename_all = Some(lit_str(&n)?);
                        } else {
                            consume(&n)?;
                        }
                        Ok(())
                    })?;
                }
            } else if m.path.is_ident("default") {
                s.default = true;
                consume(&m)?;
            } else if m.path.is_ident("skip") {
                s.skip = true;
            } else if m.path.is_ident("flatten") {
                s.flatten = true;
            } else if m.path.is_ident("untagged") {
                s.untagged = true;
            } else if m.path.is_ident("tag") {
                s.tag = Some(lit_str(&m)?);
            } else if m.path.is_ident("content") {
                s.content = Some(lit_str(&m)?);
            } else {
                consume(&m)?;
            }
            Ok(())
        });
    }
    s
}

fn words(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = s.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' || c == '-' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if c.is_uppercase() && !cur.is_empty() {
            let prev_lower = chars[i - 1].is_lowercase() || chars[i - 1].is_ascii_digit();
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if prev_lower || next_lower {
                out.push(std::mem::take(&mut cur));
            }
        }
        cur.push(c);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out.into_iter().map(|w| w.to_lowercase()).collect()
}

fn cap(w: &str) -> String {
    let mut c = w.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn apply_case(name: &str, rule: &str) -> String {
    let w = words(name);
    match rule {
        "lowercase" => w.concat(),
        "UPPERCASE" => w.concat().to_uppercase(),
        "PascalCase" => w.iter().map(|x| cap(x)).collect(),
        "camelCase" => w
            .iter()
            .enumerate()
            .map(|(i, x)| if i == 0 { x.clone() } else { cap(x) })
            .collect(),
        "snake_case" => w.join("_"),
        "SCREAMING_SNAKE_CASE" => w.join("_").to_uppercase(),
        "kebab-case" => w.join("-"),
        "SCREAMING-KEBAB-CASE" => w.join("-").to_uppercase(),
        _ => name.to_string(),
    }
}

fn type_args(seg: &syn::PathSegment) -> Vec<&Type> {
    match &seg.arguments {
        PathArguments::AngleBracketed(a) => a
            .args
            .iter()
            .filter_map(|g| match g {
                GenericArgument::Type(t) => Some(t),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

pub struct SchemaGen<'a> {
    scan: &'a Scan,
    by_name: HashMap<String, Vec<usize>>,
    /// (type name, file) -> component name
    assigned: HashMap<(String, String), String>,
    used: HashSet<String>,
    pub components: BTreeMap<String, Value>,
}

fn nullable(s: Value) -> Value {
    if s.get("$ref").is_some() || s.get("oneOf").is_some() || s.get("anyOf").is_some() {
        return json!({"oneOf": [s, {"type": "null"}]});
    }
    if let Some(t) = s.get("type").and_then(|t| t.as_str()).map(String::from) {
        let mut s = s;
        s["type"] = json!([t, "null"]);
        return s;
    }
    s
}

impl<'a> SchemaGen<'a> {
    pub fn new(scan: &'a Scan) -> Self {
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, t) in scan.types.iter().enumerate() {
            by_name.entry(t.name.clone()).or_default().push(i);
        }
        Self {
            scan,
            by_name,
            assigned: HashMap::new(),
            used: HashSet::new(),
            components: BTreeMap::new(),
        }
    }

    fn pick(&self, name: &str, ctx_file: &str) -> Option<&'a TypeDef> {
        let idx = self.by_name.get(name)?;
        let cands: Vec<&TypeDef> = idx.iter().map(|&i| &self.scan.types[i]).collect();
        let ctx_crate = ctx_file.split('/').take(2).collect::<Vec<_>>().join("/");
        cands
            .iter()
            .find(|c| c.file == ctx_file)
            .or_else(|| cands.iter().find(|c| c.file.starts_with(&ctx_crate)))
            .or_else(|| cands.iter().find(|c| c.is_web))
            .or_else(|| cands.first())
            .copied()
    }

    fn component_ref(&mut self, name: &str, ctx_file: &str) -> Value {
        let Some(def) = self.pick(name, ctx_file) else {
            return json!({});
        };
        let key = (def.name.clone(), def.file.clone());
        if let Some(c) = self.assigned.get(&key) {
            return json!({"$ref": format!("#/components/schemas/{c}")});
        }
        let mut comp = def.name.clone();
        if self.used.contains(&comp) {
            let stem = std::path::Path::new(&def.file)
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            comp = format!("{}_{}", def.name, stem);
        }
        let mut n = 2;
        let base = comp.clone();
        while self.used.contains(&comp) {
            comp = format!("{base}{n}");
            n += 1;
        }
        self.used.insert(comp.clone());
        self.assigned.insert(key, comp.clone());
        self.components.insert(comp.clone(), json!({}));
        let schema = self.def_schema(def);
        self.components.insert(comp.clone(), schema);
        json!({"$ref": format!("#/components/schemas/{comp}")})
    }

    pub fn type_schema(&mut self, ty: &Type, ctx_file: &str) -> Value {
        match ty {
            Type::Reference(r) => self.type_schema(&r.elem, ctx_file),
            Type::Paren(p) => self.type_schema(&p.elem, ctx_file),
            Type::Group(g) => self.type_schema(&g.elem, ctx_file),
            Type::Array(a) => {
                json!({"type": "array", "items": self.type_schema(&a.elem, ctx_file)})
            }
            Type::Slice(a) => {
                json!({"type": "array", "items": self.type_schema(&a.elem, ctx_file)})
            }
            Type::Tuple(t) => {
                if t.elems.is_empty() {
                    json!({"type": "null"})
                } else {
                    let items: Vec<Value> = t
                        .elems
                        .iter()
                        .map(|e| self.type_schema(e, ctx_file))
                        .collect();
                    json!({"type": "array", "prefixItems": items, "minItems": items.len(), "maxItems": items.len()})
                }
            }
            Type::Path(p) => {
                let Some(seg) = p.path.segments.last() else {
                    return json!({});
                };
                let name = seg.ident.to_string();
                let args = type_args(seg);
                match name.as_str() {
                    "String" | "str" | "char" | "PathBuf" | "OsString" | "Uuid" => {
                        json!({"type": "string"})
                    }
                    "IpAddr" => json!({"type": "string", "format": "ip"}),
                    "Ipv4Addr" => json!({"type": "string", "format": "ipv4"}),
                    "Ipv6Addr" => json!({"type": "string", "format": "ipv6"}),
                    "SocketAddr" => json!({"type": "string"}),
                    "DateTime" | "NaiveDateTime" | "SystemTime" => {
                        json!({"type": "string", "format": "date-time"})
                    }
                    "bool" => json!({"type": "boolean"}),
                    "u8" | "u16" | "u32" | "i8" | "i16" | "i32" => {
                        json!({"type": "integer", "format": "int32"})
                    }
                    "u64" | "i64" | "usize" | "isize" | "u128" | "i128" => {
                        json!({"type": "integer", "format": "int64"})
                    }
                    "f32" | "f64" => json!({"type": "number"}),
                    "Value" => json!({}),
                    "Option" => match args.first() {
                        Some(t) => nullable(self.type_schema(t, ctx_file)),
                        None => json!({}),
                    },
                    "Box" | "Arc" | "Rc" | "Cow" | "Mutex" | "RwLock" | "Cell" | "RefCell" => {
                        match args.first() {
                            Some(t) => self.type_schema(t, ctx_file),
                            None => json!({}),
                        }
                    }
                    "Vec" | "VecDeque" | "HashSet" | "BTreeSet" => match args.first() {
                        Some(t) => json!({"type": "array", "items": self.type_schema(t, ctx_file)}),
                        None => json!({"type": "array"}),
                    },
                    "HashMap" | "BTreeMap" | "IndexMap" => {
                        let v = args
                            .get(1)
                            .map(|t| self.type_schema(t, ctx_file))
                            .unwrap_or_else(|| json!({}));
                        json!({"type": "object", "additionalProperties": v})
                    }
                    "Result" => match args.first() {
                        Some(t) => self.type_schema(t, ctx_file),
                        None => json!({}),
                    },
                    _ => self.component_ref(&name, ctx_file),
                }
            }
            _ => json!({}),
        }
    }

    fn named_fields(
        &mut self,
        fields: &syn::FieldsNamed,
        c: &Serde,
        ctx: &str,
    ) -> (Map<String, Value>, Vec<String>, Vec<Value>) {
        let mut props = Map::new();
        let mut required = Vec::new();
        let mut flat = Vec::new();
        for f in &fields.named {
            let fs = serde_attrs(&f.attrs);
            if fs.skip {
                continue;
            }
            let ident = f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
            let ident = ident.strip_prefix("r#").unwrap_or(&ident).to_string();
            if fs.flatten {
                let s = self.type_schema(&f.ty, ctx);
                flat.push(s);
                continue;
            }
            let name = fs.rename.clone().unwrap_or_else(|| match &c.rename_all {
                Some(r) => apply_case(&ident, r),
                None => ident.clone(),
            });
            let mut s = self.type_schema(&f.ty, ctx);
            let d = doc_of(&f.attrs);
            if !d.is_empty() {
                if s.get("$ref").is_some() {
                    s = json!({"allOf": [s], "description": d});
                } else if let Some(o) = s.as_object_mut() {
                    o.insert("description".into(), json!(d));
                }
            }
            let is_opt = matches!(&f.ty, Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Option"));
            if !is_opt && !fs.default && !c.default {
                required.push(name.clone());
            }
            props.insert(name, s);
        }
        (props, required, flat)
    }

    fn def_schema(&mut self, def: &TypeDef) -> Value {
        let ctx = def.file.clone();
        match &def.item {
            TypeItem::Struct(s) => {
                let c = serde_attrs(&s.attrs);
                let doc = doc_of(&s.attrs);
                let mut out = match &s.fields {
                    Fields::Named(n) => {
                        let (props, req, flat) = self.named_fields(n, &c, &ctx);
                        let mut o = json!({"type": "object", "properties": props});
                        if !req.is_empty() {
                            o["required"] = json!(req);
                        }
                        if !flat.is_empty() {
                            let mut all = vec![o];
                            all.extend(flat);
                            json!({"allOf": all})
                        } else {
                            o
                        }
                    }
                    Fields::Unnamed(u) if u.unnamed.len() == 1 => {
                        self.type_schema(&u.unnamed[0].ty, &ctx)
                    }
                    Fields::Unnamed(u) => {
                        let items: Vec<Value> = u
                            .unnamed
                            .iter()
                            .map(|f| self.type_schema(&f.ty, &ctx))
                            .collect();
                        json!({"type": "array", "prefixItems": items})
                    }
                    Fields::Unit => json!({"type": "null"}),
                };
                if !doc.is_empty() && out.is_object() && out.get("$ref").is_none() {
                    out["description"] = json!(doc);
                }
                out
            }
            TypeItem::Enum(e) => {
                let c = serde_attrs(&e.attrs);
                let doc = doc_of(&e.attrs);
                let vname = |v: &syn::Variant| -> String {
                    let vs = serde_attrs(&v.attrs);
                    vs.rename.unwrap_or_else(|| match &c.rename_all {
                        Some(r) => apply_case(&v.ident.to_string(), r),
                        None => v.ident.to_string(),
                    })
                };
                let all_unit = e.variants.iter().all(|v| matches!(v.fields, Fields::Unit));
                let mut out = if all_unit && !c.untagged {
                    let vals: Vec<String> = e
                        .variants
                        .iter()
                        .filter(|v| !serde_attrs(&v.attrs).skip)
                        .map(vname)
                        .collect();
                    json!({"type": "string", "enum": vals})
                } else {
                    let mut alts = Vec::new();
                    for v in &e.variants {
                        if serde_attrs(&v.attrs).skip {
                            continue;
                        }
                        let n = vname(v);
                        let inner = match &v.fields {
                            Fields::Unit => None,
                            Fields::Unnamed(u) if u.unnamed.len() == 1 => {
                                Some(self.type_schema(&u.unnamed[0].ty, &ctx))
                            }
                            Fields::Unnamed(u) => {
                                let items: Vec<Value> = u
                                    .unnamed
                                    .iter()
                                    .map(|f| self.type_schema(&f.ty, &ctx))
                                    .collect();
                                Some(json!({"type": "array", "prefixItems": items}))
                            }
                            Fields::Named(nf) => {
                                let vc = Serde::default();
                                let (props, req, _) = self.named_fields(nf, &vc, &ctx);
                                let mut o = json!({"type": "object", "properties": props});
                                if !req.is_empty() {
                                    o["required"] = json!(req);
                                }
                                Some(o)
                            }
                        };
                        let alt = if c.untagged {
                            inner.unwrap_or_else(|| json!({"type": "null"}))
                        } else if let Some(tag) = &c.tag {
                            match (&c.content, inner) {
                                (Some(content), inner) => {
                                    let mut p = Map::new();
                                    p.insert(tag.clone(), json!({"const": n}));
                                    if let Some(i) = inner {
                                        p.insert(content.clone(), i);
                                    }
                                    json!({"type": "object", "properties": p, "required": [tag]})
                                }
                                (None, Some(i)) if i.get("properties").is_some() => {
                                    let mut i = i;
                                    i["properties"][tag] = json!({"const": n});
                                    let mut req =
                                        i["required"].as_array().cloned().unwrap_or_default();
                                    req.insert(0, json!(tag));
                                    i["required"] = json!(req);
                                    i
                                }
                                (None, _) => json!({
                                    "type": "object",
                                    "properties": {tag.clone(): {"const": n}},
                                    "required": [tag]
                                }),
                            }
                        } else {
                            match inner {
                                None => json!({"const": n}),
                                Some(i) => json!({
                                    "type": "object",
                                    "properties": {n.clone(): i},
                                    "required": [n]
                                }),
                            }
                        };
                        alts.push(alt);
                    }
                    json!({"oneOf": alts})
                };
                if !doc.is_empty() {
                    out["description"] = json!(doc);
                }
                out
            }
        }
    }
}
