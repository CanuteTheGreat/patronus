//! Reads the patronus-web sources: every `.route("path", get(h).post(h2))` call, the handler
//! functions (doc comment, extractor and return types), the Askama template structs and the
//! serde type definitions of the whole workspace.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::visit::Visit;
use syn::{Attribute, Expr, ItemEnum, ItemStruct, Lit, Meta, Type};

pub const METHODS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "head", "options", "any",
];

#[derive(Debug, Clone)]
pub struct HandlerRef {
    /// Last path segment (`overview` for `built::overview`), or `<closure>` / `<expr>`.
    pub name: String,
    /// The segments before it (`["built"]`, `["crate", "auth"]`).
    pub qualifier: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RouteDef {
    /// File relative to `crates/patronus-web/src`.
    pub file: String,
    pub fn_name: String,
    pub path: String,
    pub methods: Vec<(String, HandlerRef)>,
}

#[derive(Debug, Clone)]
pub struct FnInfo {
    pub file: String,
    pub name: String,
    /// Names of the inline `mod`s the function sits in (`["built"]`).
    pub mod_path: Vec<String>,
    pub doc: String,
    pub inputs: Vec<Type>,
    pub output: Option<Type>,
    /// Every identifier used as the last segment of a path in the body (finds the Askama
    /// template struct a page handler renders).
    pub body_idents: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub enum TypeItem {
    Struct(ItemStruct),
    Enum(ItemEnum),
}

#[derive(Debug, Clone)]
pub struct TypeDef {
    pub name: String,
    /// `crates/<crate>/src/...` relative to the repo root.
    pub file: String,
    pub is_web: bool,
    pub item: TypeItem,
}

#[derive(Debug, Default)]
pub struct Scan {
    pub routes: Vec<RouteDef>,
    /// Route calls whose path or handler could not be read (must stay empty).
    pub unparsed: Vec<String>,
    pub fns: Vec<FnInfo>,
    /// (source file, Askama struct name) -> template file name.
    pub templates: BTreeMap<(String, String), String>,
    pub types: Vec<TypeDef>,
    /// Literal prefixes of `people_only` in `require_session` (not open to API keys).
    pub people_only: Vec<String>,
}

pub fn doc_of(attrs: &[Attribute]) -> String {
    let mut lines = Vec::new();
    for a in attrs {
        if a.path().is_ident("doc") {
            if let Meta::NameValue(nv) = &a.meta {
                if let Expr::Lit(l) = &nv.value {
                    if let Lit::Str(s) = &l.lit {
                        let t = s.value();
                        lines.push(t.strip_prefix(' ').unwrap_or(&t).trim_end().to_string());
                    }
                }
            }
        }
    }
    lines.join("\n").trim().to_string()
}

fn is_test_attr(a: &Attribute) -> bool {
    let p = a.path();
    if p.is_ident("test") {
        return true;
    }
    if let Some(last) = p.segments.last() {
        if last.ident == "test" {
            return true; // tokio::test
        }
    }
    if p.is_ident("cfg") {
        let t = a.meta.to_token_stream().to_string().replace(' ', "");
        return t == "cfg(test)" || t.starts_with("cfg(all(test");
    }
    false
}

struct Walker<'a> {
    file: String,
    scan: &'a mut Scan,
    fn_stack: Vec<(String, HashMap<String, Vec<Expr>>)>,
    mods: Vec<String>,
}

fn collect_lets(block: &syn::Block) -> HashMap<String, Vec<Expr>> {
    struct L(HashMap<String, Vec<Expr>>);
    impl<'ast> Visit<'ast> for L {
        fn visit_local(&mut self, l: &'ast syn::Local) {
            if let (syn::Pat::Ident(pi), Some(init)) = (&l.pat, &l.init) {
                self.0
                    .entry(pi.ident.to_string())
                    .or_default()
                    .push((*init.expr).clone());
            }
            syn::visit::visit_local(self, l);
        }
    }
    let mut l = L(HashMap::new());
    l.visit_block(block);
    l.0
}

fn handler_ref(e: Option<&Expr>) -> HandlerRef {
    match e {
        Some(Expr::Path(p)) => {
            let segs: Vec<String> = p
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            let name = segs.last().cloned().unwrap_or_default();
            HandlerRef {
                name,
                qualifier: segs[..segs.len().saturating_sub(1)].to_vec(),
            }
        }
        Some(Expr::Closure(_)) => HandlerRef {
            name: "<closure>".into(),
            qualifier: vec![],
        },
        _ => HandlerRef {
            name: "<expr>".into(),
            qualifier: vec![],
        },
    }
}

fn parse_mr(
    e: &Expr,
    lets: &HashMap<String, Vec<Expr>>,
    out: &mut Vec<(String, HandlerRef)>,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    match e {
        Expr::Call(c) => {
            if let Expr::Path(p) = &*c.func {
                if let Some(last) = p.path.segments.last() {
                    let n = last.ident.to_string();
                    if METHODS.contains(&n.as_str()) {
                        out.push((n, handler_ref(c.args.first())));
                    }
                }
            }
        }
        Expr::MethodCall(m) => {
            parse_mr(&m.receiver, lets, out, depth + 1);
            let n = m.method.to_string();
            if METHODS.contains(&n.as_str()) {
                out.push((n, handler_ref(m.args.first())));
            }
        }
        Expr::Path(p) => {
            if let Some(id) = p.path.get_ident() {
                if let Some(v) = lets.get(&id.to_string()) {
                    for x in v {
                        parse_mr(x, lets, out, depth + 1);
                    }
                }
            }
        }
        Expr::Paren(p) => parse_mr(&p.expr, lets, out, depth + 1),
        Expr::Group(g) => parse_mr(&g.expr, lets, out, depth + 1),
        _ => {}
    }
}

impl<'a, 'ast> Visit<'ast> for Walker<'a> {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if m.attrs.iter().any(is_test_attr) {
            return;
        }
        self.mods.push(m.ident.to_string());
        syn::visit::visit_item_mod(self, m);
        self.mods.pop();
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if f.attrs.iter().any(is_test_attr) {
            return;
        }
        let name = f.sig.ident.to_string();
        self.record_fn(&name, &f.attrs, &f.sig, &f.block);
        self.fn_stack.push((name, collect_lets(&f.block)));
        syn::visit::visit_item_fn(self, f);
        self.fn_stack.pop();
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if f.attrs.iter().any(is_test_attr) {
            return;
        }
        let name = f.sig.ident.to_string();
        self.fn_stack.push((name, collect_lets(&f.block)));
        syn::visit::visit_impl_item_fn(self, f);
        self.fn_stack.pop();
    }

    fn visit_item_struct(&mut self, s: &'ast ItemStruct) {
        for a in &s.attrs {
            if a.path().is_ident("template") {
                let mut path = None;
                let _ = a.parse_nested_meta(|m| {
                    if m.path.is_ident("path") {
                        let v: syn::LitStr = m.value()?.parse()?;
                        path = Some(v.value());
                    } else if m.input.peek(syn::Token![=]) {
                        let _: Expr = m.value()?.parse()?;
                    }
                    Ok(())
                });
                if let Some(p) = path {
                    self.scan
                        .templates
                        .insert((self.file.clone(), s.ident.to_string()), p);
                }
            }
        }
        syn::visit::visit_item_struct(self, s);
    }

    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        if m.method == "route" && m.args.len() == 2 {
            let (fn_name, lets) = match self.fn_stack.last() {
                Some((n, l)) => (n.clone(), l.clone()),
                None => (String::new(), HashMap::new()),
            };
            let path = match &m.args[0] {
                Expr::Lit(l) => match &l.lit {
                    Lit::Str(s) => Some(s.value()),
                    _ => None,
                },
                _ => None,
            };
            match path {
                Some(path) => {
                    let mut methods = Vec::new();
                    parse_mr(&m.args[1], &lets, &mut methods, 0);
                    if methods.is_empty() {
                        self.scan.unparsed.push(format!(
                            "{}::{fn_name}: route {path} has no get/post/... handler I can read",
                            self.file
                        ));
                    }
                    self.scan.routes.push(RouteDef {
                        file: self.file.clone(),
                        fn_name,
                        path,
                        methods,
                    });
                }
                None => self.scan.unparsed.push(format!(
                    "{}::{fn_name}: route path is not a string literal",
                    self.file
                )),
            }
        }
        syn::visit::visit_expr_method_call(self, m);
    }
}

impl<'a> Walker<'a> {
    fn record_fn(
        &mut self,
        name: &str,
        attrs: &[Attribute],
        sig: &syn::Signature,
        block: &syn::Block,
    ) {
        struct Idents(BTreeSet<String>);
        impl<'ast> Visit<'ast> for Idents {
            fn visit_path(&mut self, p: &'ast syn::Path) {
                if let Some(l) = p.segments.last() {
                    self.0.insert(l.ident.to_string());
                }
                syn::visit::visit_path(self, p);
            }
        }
        let mut ids = Idents(BTreeSet::new());
        ids.visit_block(block);
        let inputs = sig
            .inputs
            .iter()
            .filter_map(|a| match a {
                syn::FnArg::Typed(t) => Some((*t.ty).clone()),
                _ => None,
            })
            .collect();
        let output = match &sig.output {
            syn::ReturnType::Type(_, t) => Some((**t).clone()),
            _ => None,
        };
        self.scan.fns.push(FnInfo {
            file: self.file.clone(),
            name: name.to_string(),
            mod_path: self.mods.clone(),
            doc: doc_of(attrs),
            inputs,
            output,
            body_idents: ids.0,
        });
    }
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut v: Vec<_> = rd.flatten().collect();
    v.sort_by_key(|e| e.file_name());
    for e in v {
        let p = e.path();
        let n = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if n == "target" || n == "tests" || n.starts_with('.') {
                continue;
            }
            rs_files(&p, out);
        } else if n.ends_with(".rs") {
            out.push(p);
        }
    }
}

struct TypeCollector<'a> {
    file: String,
    is_web: bool,
    out: &'a mut Vec<TypeDef>,
}

impl<'a, 'ast> Visit<'ast> for TypeCollector<'a> {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if m.attrs.iter().any(is_test_attr) {
            return;
        }
        syn::visit::visit_item_mod(self, m);
    }
    fn visit_item_struct(&mut self, s: &'ast ItemStruct) {
        self.out.push(TypeDef {
            name: s.ident.to_string(),
            file: self.file.clone(),
            is_web: self.is_web,
            item: TypeItem::Struct(s.clone()),
        });
    }
    fn visit_item_enum(&mut self, s: &'ast ItemEnum) {
        self.out.push(TypeDef {
            name: s.ident.to_string(),
            file: self.file.clone(),
            is_web: self.is_web,
            item: TypeItem::Enum(s.clone()),
        });
    }
}

fn people_only(file: &syn::File) -> Vec<String> {
    struct F {
        found: Vec<String>,
    }
    struct Lits(Vec<String>);
    impl<'ast> Visit<'ast> for Lits {
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            if m.method == "starts_with" {
                if let Some(Expr::Lit(l)) = m.args.first() {
                    if let Lit::Str(s) = &l.lit {
                        self.0.push(s.value());
                    }
                }
            }
            syn::visit::visit_expr_method_call(self, m);
        }
        fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
            if matches!(b.op, syn::BinOp::Ne(_)) {
                if let Expr::Lit(l) = &*b.right {
                    if let Lit::Str(s) = &l.lit {
                        self.0.push(format!("!{}", s.value()));
                    }
                }
            }
            syn::visit::visit_expr_binary(self, b);
        }
    }
    impl<'ast> Visit<'ast> for F {
        fn visit_local(&mut self, l: &'ast syn::Local) {
            if let (syn::Pat::Ident(pi), Some(init)) = (&l.pat, &l.init) {
                if pi.ident == "people_only" {
                    let mut ls = Lits(vec![]);
                    ls.visit_expr(&init.expr);
                    self.found.extend(ls.0);
                }
            }
            syn::visit::visit_local(self, l);
        }
    }
    let mut f = F { found: vec![] };
    f.visit_file(file);
    f.found
}

/// Scan `<root>/crates/patronus-web/src` for routes and handlers and every crate for types.
pub fn scan(root: &Path) -> Result<Scan, String> {
    let mut s = Scan::default();
    let web_src = root.join("crates/patronus-web/src");
    let mut files = Vec::new();
    rs_files(&web_src, &mut files);
    for f in &files {
        let rel = f
            .strip_prefix(&web_src)
            .unwrap()
            .to_string_lossy()
            .to_string();
        // test-only files are `#[cfg(test)] mod x;` in routes/mod.rs
        if rel.ends_with("_tests.rs") {
            continue;
        }
        let src = fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
        let ast = syn::parse_file(&src).map_err(|e| format!("{rel}: {e}"))?;
        if rel == "routes/mod.rs" {
            s.people_only = people_only(&ast);
        }
        let mut w = Walker {
            file: rel,
            scan: &mut s,
            fn_stack: vec![],
            mods: vec![],
        };
        w.visit_file(&ast);
    }
    // types: every crate of the workspace
    let crates = root.join("crates");
    let mut dirs: Vec<_> = fs::read_dir(&crates)
        .map_err(|e| format!("{}: {e}", crates.display()))?
        .flatten()
        .map(|e| e.path())
        .collect();
    dirs.sort();
    for d in dirs {
        let name = d.file_name().unwrap().to_string_lossy().to_string();
        if name == "patronus-openapi" {
            continue;
        }
        let mut fs_ = Vec::new();
        rs_files(&d.join("src"), &mut fs_);
        for f in fs_ {
            let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
            if rel.ends_with("_tests.rs") {
                continue;
            }
            let Ok(src) = fs::read_to_string(&f) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&src) else {
                continue;
            };
            let mut tc = TypeCollector {
                file: rel,
                is_web: name == "patronus-web",
                out: &mut s.types,
            };
            tc.visit_file(&ast);
        }
    }
    Ok(s)
}

impl Scan {
    /// The function a route's handler refers to.
    pub fn resolve(&self, route_file: &str, h: &HandlerRef) -> Option<&FnInfo> {
        let cands: Vec<&FnInfo> = self.fns.iter().filter(|f| f.name == h.name).collect();
        if cands.is_empty() {
            return None;
        }
        for q in h.qualifier.iter().rev() {
            for c in &cands {
                if c.file == route_file && c.mod_path.last() == Some(q) {
                    return Some(c);
                }
            }
            for c in &cands {
                let stem = Path::new(&c.file)
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                if &stem == q {
                    return Some(c);
                }
            }
        }
        if let Some(c) = cands.iter().find(|c| c.file == route_file) {
            return Some(c);
        }
        if cands.len() == 1 {
            return Some(cands[0]);
        }
        None
    }
}
