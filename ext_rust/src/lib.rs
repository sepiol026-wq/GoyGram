// CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyRuntimeError;
use pyo3::exceptions::PyValueError;
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Payload}, Nonce};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::sync::RwLock;

static METHODS: RwLock<Option<HashMap<String, TlMethod>>> = RwLock::new(None);
static CTORS: RwLock<Option<HashMap<String, TlConstructor>>> = RwLock::new(None);
static SCHEMA_LAYER: RwLock<u32> = RwLock::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlFieldDef {
    name: String,
    #[serde(rename = "type")]
    ftype: String,
    #[serde(default)]
    flag_bit: Option<u32>,
    #[serde(default)]
    flags_group: Option<String>,
    #[serde(default)]
    is_bare: bool,
    #[serde(default)]
    is_vector: bool,
    #[serde(default)]
    vector_inner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlMethod {
    cid: u32,
    fields: Vec<TlFieldDef>,
    #[serde(default)]
    has_flags: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlConstructor {
    cid: u32,
    fields: Vec<TlFieldDef>,
    #[serde(default)]
    has_flags: bool,
}

#[derive(Debug, Deserialize)]
struct SchemaInput {
    #[serde(default)]
    layer: u32,
    methods: HashMap<String, TlMethod>,
    #[serde(default)]
    constructors: HashMap<String, TlConstructor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemaInfo {
    layer: u32,
    #[serde(default)]
    methods: u32,
    #[serde(default)]
    constructors: u32,
}

fn pack_schema(methods: &HashMap<String, TlMethod>, ctors: &HashMap<String, TlConstructor>) -> SchemaInfo {
    SchemaInfo {
        layer: *SCHEMA_LAYER.read().unwrap(),
        methods: methods.len() as u32,
        constructors: ctors.len() as u32,
    }
}

static BOOTSTRAP_SCHEMA_JSON: &str = include_str!("bootstrap.json");

fn apply_bootstrap() {
    let mut m = METHODS.write().unwrap();
    let mut c = CTORS.write().unwrap();
    if m.is_none() && c.is_none() {
        if let Ok(raw) = serde_json::from_str::<SchemaInput>(BOOTSTRAP_SCHEMA_JSON) {
            *m = Some(raw.methods);
            *c = Some(raw.constructors);
        }
    }
}

#[pyfunction]
fn load_schema(schema_json: &str) -> PyResult<String> {
    let raw: SchemaInput = match serde_json::from_str::<SchemaInput>(schema_json) {
        Ok(s) => s,
        Err(_) => {
            let methods_map: HashMap<String, TlMethod> = serde_json::from_str(schema_json)
                .map_err(|e| PyValueError::new_err(format!("schema parsing failed: {}", e)))?;
            SchemaInput {
                layer: 0,
                methods: methods_map,
                constructors: HashMap::new(),
            }
        }
    };

    let info = SchemaInfo {
        layer: raw.layer,
        methods: raw.methods.len() as u32,
        constructors: raw.constructors.len() as u32,
    };

    {
        let mut m = METHODS.write().unwrap();
        let mut c = CTORS.write().unwrap();
        *SCHEMA_LAYER.write().unwrap() = raw.layer;
        *m = Some(raw.methods);
        *c = Some(raw.constructors);
    }

    Ok(serde_json::to_string(&info).unwrap())
}

#[pyfunction]
fn schema_info() -> PyResult<String> {
    let m = METHODS.read().unwrap();
    let c = CTORS.read().unwrap();
    match (&*m, &*c) {
        (Some(methods), Some(ctors)) => {
            let info = pack_schema(methods, ctors);
            Ok(serde_json::to_string(&info).unwrap())
        }
        _ => Ok(r#"{"methods":0,"constructors":0}"#.to_string()),
    }
}

fn get_ctor_by_cid(cid: u32) -> Option<(String, TlConstructor)> {
    let c = CTORS.read().unwrap();
    let ctors = c.as_ref()?;
    for (name, ctor) in ctors {
        if ctor.cid == cid {
            return Some((name.clone(), ctor.clone()));
        }
    }
    None
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, String> {
    if *pos + 4 > data.len() {
        return Err("unexpected eof".to_string());
    }
    let v = u32::from_le_bytes(data[*pos..*pos+4].try_into().unwrap());
    *pos += 4;
    Ok(v)
}

fn read_i32(data: &[u8], pos: &mut usize) -> Result<i32, String> {
    Ok(read_u32(data, pos)? as i32)
}

fn read_i64(data: &[u8], pos: &mut usize) -> Result<i64, String> {
    if *pos + 8 > data.len() {
        return Err("unexpected eof".to_string());
    }
    let v = i64::from_le_bytes(data[*pos..*pos+8].try_into().unwrap());
    *pos += 8;
    Ok(v)
}

fn read_f64(data: &[u8], pos: &mut usize) -> Result<f64, String> {
    if *pos + 8 > data.len() {
        return Err("unexpected eof".to_string());
    }
    let v = f64::from_le_bytes(data[*pos..*pos+8].try_into().unwrap());
    *pos += 8;
    Ok(v)
}

fn read_bytes(data: &[u8], pos: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    if *pos + len > data.len() {
        return Err("unexpected eof".to_string());
    }
    let v = data[*pos..*pos+len].to_vec();
    *pos += len;
    Ok(v)
}

fn read_tl_string(data: &[u8], pos: &mut usize) -> Result<String, String> {
    if *pos >= data.len() {
        return Err("unexpected eof".to_string());
    }
    let len = data[*pos] as usize;
    *pos += 1;
    let str_len = if len <= 253 {
        len
    } else if len == 254 {
        if *pos + 3 > data.len() {
            return Err("unexpected eof".to_string());
        }
        let l = u32::from_le_bytes([data[*pos], data[*pos+1], data[*pos+2], 0]) as usize;
        *pos += 3;
        l
    } else {
        return Err("bad string len".to_string());
    };
    let raw = read_bytes(data, pos, str_len)?;
    let padding = (4 - ((1 + if len <= 253 { 0 } else { 3 } + str_len) % 4)) % 4;
    *pos += padding;
    String::from_utf8(raw).map_err(|e| format!("utf8: {}", e))
}

fn read_tl_bytes_raw(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
    if *pos >= data.len() {
        return Err("unexpected eof".to_string());
    }
    let len = data[*pos] as usize;
    *pos += 1;
    let byte_len = if len <= 253 {
        len
    } else if len == 254 {
        if *pos + 3 > data.len() {
            return Err("unexpected eof".to_string());
        }
        let l = u32::from_le_bytes([data[*pos], data[*pos+1], data[*pos+2], 0]) as usize;
        *pos += 3;
        l
    } else {
        return Err("bad bytes len".to_string());
    };
    let raw = read_bytes(data, pos, byte_len)?;
    let padding = (4 - ((1 + if len <= 253 { 0 } else { 3 } + byte_len) % 4)) % 4;
    *pos += padding;
    Ok(raw)
}

fn read_field_value(data: &[u8], pos: &mut usize, f: &TlFieldDef) -> Result<serde_json::Value, String> {
    match f.ftype.as_str() {
        "#" => Ok(serde_json::json!(read_u32(data, pos)?)),
        "int" | "Int" => Ok(serde_json::json!(read_i32(data, pos)?)),
        "long" | "Long" => Ok(serde_json::json!(read_i64(data, pos)?)),
        "int128" => {
            let b = read_bytes(data, pos, 16)?;
            Ok(serde_json::json!(hex::encode(b)))
        }
        "int256" => {
            let b = read_bytes(data, pos, 32)?;
            Ok(serde_json::json!(hex::encode(b)))
        }
        "string" | "String" => {
            let s = read_tl_string(data, pos)?;
            Ok(serde_json::json!(s))
        }
        "bytes" | "Bytes" => {
            let b = read_tl_bytes_raw(data, pos)?;
            Ok(serde_json::json!(hex::encode(b)))
        }
        "double" | "Double" => Ok(serde_json::json!(read_f64(data, pos)?)),
        "Bool" | "boolTrue" | "boolFalse" => {
            let cid = read_u32(data, pos)?;
            Ok(serde_json::json!(cid == 0x997275b5))
        }
        "true" | "True" => Ok(serde_json::json!(true)),
        _ => {
            if f.is_vector {
                read_tl_vector(data, pos, f)
            } else {
                deserialize_tl(data, pos)
            }
        }
    }
}

fn read_tl_vector(data: &[u8], pos: &mut usize, f: &TlFieldDef) -> Result<serde_json::Value, String> {
    let vec_cid = read_u32(data, pos)?;
    if vec_cid != 0x1cb5c415 {
        return Err(format!("not a vector: {:08x}", vec_cid));
    }
    let count = read_i32(data, pos)?;
    if count < 0 || count > 1_000_000 { return Err("invalid vector count".to_string()); }
    let count = count as usize;
    let inner_type = f.vector_inner.as_deref().unwrap_or("int");
    let inner_field = TlFieldDef {
        name: "item".to_string(),
        ftype: inner_type.to_string(),
        flag_bit: None,
        flags_group: None,
        is_bare: false,
        is_vector: false,
        vector_inner: None,
    };
    let mut arr = Vec::new();
    for _ in 0..count {
        let val = read_field_value(data, pos, &inner_field)?;
        arr.push(val);
    }
    Ok(serde_json::json!(arr))
}

fn deserialize_fields(data: &[u8], pos: &mut usize, fields: &[TlFieldDef], has_flags: bool, name: &str) -> Result<serde_json::Value, String> {
    let mut obj = serde_json::Map::new();
    obj.insert("_".to_string(), serde_json::json!(name));
    let mut flags_map: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    for f in fields {
        if f.ftype == "#" {
            let val = read_u32(data, pos)?;
            flags_map.insert(f.name.clone(), val);
            obj.insert(f.name.clone(), serde_json::json!(val));
            continue;
        }

        if has_flags && f.flag_bit.is_some() {
            let group = f.flags_group.as_deref().unwrap_or("flags");
            let flags_val = flags_map.get(group).copied().unwrap_or(0);
            let bit = f.flag_bit.unwrap();
            if flags_val & (1 << bit) == 0 {
                if f.is_bare {
                    obj.insert(f.name.clone(), serde_json::json!(false));
                }
                continue;
            }
            if f.is_bare {
                obj.insert(f.name.clone(), serde_json::json!(true));
                continue;
            }
        }

        let val = read_field_value(data, pos, f)?;
        obj.insert(f.name.clone(), val);
    }

    Ok(serde_json::Value::Object(obj))
}

fn deserialize_tl(data: &[u8], pos: &mut usize) -> Result<serde_json::Value, String> {
    let start = *pos;
    let cid = read_u32(data, pos)?;
    if let Some((name, ctor)) = get_ctor_by_cid(cid) {
        let mut result = deserialize_fields(data, pos, &ctor.fields, ctor.has_flags, &name)?;
        if let Some(obj) = result.as_object_mut() {
            obj.insert("raw".to_string(), serde_json::json!(hex::encode(&data[start..*pos])));
        }
        Ok(result)
    } else {
        let start = *pos - 4;
        let remaining = &data[start..];
        *pos = data.len();
        Ok(serde_json::json!({
            "_": "unknownConstructor",
            "cid": cid,
            "raw": hex::encode(remaining)
        }))
    }
}

#[pyfunction]
fn deserialize_constructor(data: Vec<u8>) -> PyResult<String> {
    let mut pos = 0;
    let result = deserialize_tl(&data, &mut pos)
        .map_err(|e| PyValueError::new_err(e))?;
    Ok(serde_json::to_string(&result).unwrap())
}

fn serialize_tl(name: &str, args_json: &str, cid: u32, fields: &[TlFieldDef], has_flags: bool) -> PyResult<Vec<u8>> {
    let args: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|e| PyValueError::new_err(format!("args parsing failed: {}", e)))?;

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&cid.to_le_bytes());

    if has_flags {
        let mut flags_map: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

        for f in fields {
            if let Some(bit) = f.flag_bit {
                let group = f.flags_group.as_deref().unwrap_or("flags");
                let val = args.get(&f.name);
                let has_val = match val {
                    Some(serde_json::Value::Null) | None => false,
                    Some(serde_json::Value::Bool(true)) if f.is_bare => true,
                    Some(serde_json::Value::Bool(false)) if f.is_bare => false,
                    _ => val.is_some(),
                };
                if has_val {
                    *flags_map.entry(group.to_string()).or_insert(0) |= 1 << bit;
                }
            }
        }

        for f in fields {
            if f.ftype == "#" {
                let group = &f.name;
                let fv = flags_map.get(group).copied().unwrap_or(0);
                buf.extend_from_slice(&fv.to_le_bytes());
                continue;
            }

            if f.flag_bit.is_some() {
                let val = args.get(&f.name);
                let has_val = match val {
                    Some(serde_json::Value::Null) | None => false,
                    Some(serde_json::Value::Bool(true)) if f.is_bare => true,
                    Some(serde_json::Value::Bool(false)) if f.is_bare => false,
                    _ => val.is_some(),
                };

                if !has_val {
                    continue;
                }

                if f.is_bare {
                    continue;
                }

                let fb = encode_field_value(&f, val.unwrap_or(&serde_json::Value::Null))
                    .map_err(|e| PyValueError::new_err(format!("{}:{}: {}", name, f.name, e)))?;
                buf.extend_from_slice(&fb);
            } else {
                let val = args.get(&f.name).ok_or_else(|| PyValueError::new_err(format!("{}: missing required field {}", name, f.name)))?;
                let fb = encode_field_value(&f, val)
                    .map_err(|e| PyValueError::new_err(format!("{}:{}: {}", name, f.name, e)))?;
                buf.extend_from_slice(&fb);
            }
        }
    } else {
        for f in fields {
            let val = args.get(&f.name).ok_or_else(|| PyValueError::new_err(format!("{}: missing required field {}", name, f.name)))?;
            let fb = encode_field_value(&f, val)
                .map_err(|e| PyValueError::new_err(format!("{}:{}: {}", name, f.name, e)))?;
            buf.extend_from_slice(&fb);
        }
    }

    Ok(buf)
}

fn encode_field_value(f: &TlFieldDef, val: &serde_json::Value) -> Result<Vec<u8>, String> {
    match f.ftype.as_str() {
        "#" => {
            let n = val.as_i64().ok_or("flags not int")? as u32;
            Ok(n.to_le_bytes().to_vec())
        }
        "int" | "Int" => {
            let n = val.as_i64().ok_or("int expected")? as i32;
            Ok(n.to_le_bytes().to_vec())
        }
        "long" | "Long" => {
            if val.is_string() {
                let s = val.as_str().unwrap();
                let bytes = hex::decode(s)
                    .map_err(|e| format!("hex: {}", e))?;
                Ok(bytes)
            } else if val.is_number() {
                let n = val.as_i64().ok_or("long expected")?;
                Ok(n.to_le_bytes().to_vec())
            } else {
                Err(format!("cannot encode field {} as long", f.name))
            }
        }
        "int128" => {
            if let Some(n) = val.as_i64() {
                let mut out = vec![0u8; 16];
                out[..8].copy_from_slice(&n.to_le_bytes());
                Ok(out)
            } else if let Some(s) = val.as_str() {
                let bytes = hex::decode(s).map_err(|e| format!("hex: {}", e))?;
                if bytes.len() != 16 { return Err("int128 must be 16 bytes".to_string()); }
                Ok(bytes)
            } else { Err(format!("cannot encode field {} as int128", f.name)) }
        }
        "int256" => {
            if let Some(n) = val.as_i64() {
                let mut out = vec![0u8; 32];
                out[..8].copy_from_slice(&n.to_le_bytes());
                Ok(out)
            } else if let Some(s) = val.as_str() {
                let bytes = hex::decode(s).map_err(|e| format!("hex: {}", e))?;
                if bytes.len() != 32 { return Err("int256 must be 32 bytes".to_string()); }
                Ok(bytes)
            } else { Err(format!("cannot encode field {} as int256", f.name)) }
        }
        "string" | "String" => {
            let s = val.as_str().unwrap_or("");
            encode_tl_string(s)
        }
        "bytes" | "Bytes" => {
            if val.is_string() {
                let s = val.as_str().unwrap();
                let b = hex::decode(s).map_err(|e| format!("hex: {}", e))?;
                encode_tl_bytes(&b)
            } else if val.is_array() {
                let mut b = Vec::new();
                for v in val.as_array().unwrap() {
                    let n = v.as_u64().ok_or("byte expected")? as u8;
                    b.push(n);
                }
                encode_tl_bytes(&b)
            } else {
                Err(format!("cannot encode field {} as bytes", f.name))
            }
        }
        "double" | "Double" => {
            let n = val.as_f64().ok_or("double expected")?;
            Ok(n.to_le_bytes().to_vec())
        }
        "Bool" | "boolTrue" | "boolFalse" => {
            let b = val.as_bool().unwrap_or(false);
            if b {
                Ok(0x997275b5u32.to_le_bytes().to_vec())
            } else {
                Ok(0xbc799737u32.to_le_bytes().to_vec())
            }
        }
        "true" | "True" => {
            Ok(vec![])
        }
        _ => {
            if f.is_vector {
                encode_tl_vector(f, val)
            } else if f.ftype.starts_with('!') {
                if val.is_string() {
                    let s = val.as_str().unwrap();
                    if s.is_empty() {
                        return Ok(vec![]);
                    }
                    hex::decode(s).map_err(|e| format!("hex: {}", e))
                } else {
                    Ok(vec![])
                }
            } else if val.is_string() {
                let s = val.as_str().unwrap();
                if s.is_empty() {
                    return Ok(vec![]);
                }
                hex::decode(s).map_err(|e| format!("hex: {}", e))
            } else if val.is_number() {
                let n = val.as_i64().unwrap_or(0);
                Ok(n.to_le_bytes().to_vec())
            } else if val.is_object() {
                let ctor = {
                    let c = CTORS.read().unwrap();
                    c.as_ref().and_then(|ctors| ctors.get(&f.ftype).cloned())
                };
                if let Some(def) = ctor {
                    serialize_tl(&f.ftype, &val.to_string(), def.cid, &def.fields, def.has_flags)
                        .map_err(|e| e.to_string())
                } else {
                    Err(format!("unknown constructor type {}", f.ftype))
                }
            } else {
                Err(format!("unknown TL field type {}", f.ftype))
            }
        }
    }
}

fn encode_tl_string(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    let mut buf = Vec::new();
    if b.len() <= 253 {
        buf.push(b.len() as u8);
    } else {
        buf.push(254);
        buf.extend_from_slice(&(b.len() as u32).to_le_bytes()[..3]);
    }
    buf.extend_from_slice(b);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    Ok(buf)
}

fn encode_tl_bytes(b: &[u8]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    if b.len() <= 253 {
        buf.push(b.len() as u8);
    } else {
        buf.push(254);
        buf.extend_from_slice(&(b.len() as u32).to_le_bytes()[..3]);
    }
    buf.extend_from_slice(b);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    Ok(buf)
}

fn encode_tl_vector(f: &TlFieldDef, val: &serde_json::Value) -> Result<Vec<u8>, String> {
    let arr = val.as_array().ok_or("vector expected array")?;
    let inner_type = f.vector_inner.as_deref().unwrap_or("int");

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&0x1cb5c415u32.to_le_bytes());
    buf.extend_from_slice(&(arr.len() as u32).to_le_bytes());

    for item in arr {
        let inner_field = TlFieldDef {
            name: "item".to_string(),
            ftype: inner_type.to_string(),
            flag_bit: None,
            flags_group: None,
            is_bare: false,
            is_vector: false,
            vector_inner: None,
        };
        let eb = encode_field_value(&inner_field, item)?;
        buf.extend_from_slice(&eb);
    }

    Ok(buf)
}

#[pyfunction]
fn serialize_method(py: Python<'_>, method: &str, args_json: &str) -> PyResult<Py<PyBytes>> {
    let m = METHODS.read().unwrap();
    let methods = m.as_ref()
        .ok_or_else(|| PyRuntimeError::new_err("schema not loaded"))?;

    let tl = methods.get(method)
        .ok_or_else(|| PyValueError::new_err(format!("unknown method: {}", method)))?;

    let data = serialize_tl(method, args_json, tl.cid, &tl.fields, tl.has_flags)?;
    Ok(PyBytes::new(py, &data).into())
}

#[pyfunction]
fn serialize_constructor(py: Python<'_>, name: &str, args_json: &str) -> PyResult<Py<PyBytes>> {
    let c = CTORS.read().unwrap();
    let ctors = c.as_ref()
        .ok_or_else(|| PyRuntimeError::new_err("schema not loaded"))?;

    let tl = ctors.get(name)
        .ok_or_else(|| PyValueError::new_err(format!("unknown constructor: {}", name)))?;

    let data = serialize_tl(name, args_json, tl.cid, &tl.fields, tl.has_flags)?;
    Ok(PyBytes::new(py, &data).into())
}

fn aes_ige_impl(data: &[u8], key: &[u8], iv: &[u8], direction: u8) -> Result<Vec<u8>, String> {
    if data.len() % 16 != 0 { return Err("AES-IGE data length must be a multiple of 16".to_string()); }
    if key.len() != 32 { return Err("AES-IGE key must be 32 bytes".to_string()); }
    if iv.len() != 32 { return Err("AES-IGE IV must be 32 bytes".to_string()); }
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    use aes::Aes256;

    let cipher = Aes256::new_from_slice(key).expect("invalid key size");
    let mut x = [0u8; 16];
    let mut y = [0u8; 16];
    x.copy_from_slice(&iv[..16]);
    y.copy_from_slice(&iv[16..32]);
    let mut result = data.to_vec();
    let bs = 16;
    let nblk = result.len() / bs;

    for i in 0..nblk {
        let off = i * bs;
        if direction == 0 {
            for j in 0..bs { result[off + j] ^= y[j]; }
            cipher.decrypt_block((&mut result[off..off + bs]).into());
            for j in 0..bs { result[off + j] ^= x[j]; }
            x.copy_from_slice(&data[off..off + bs]);
            y.copy_from_slice(&result[off..off + bs]);
        } else {
            for j in 0..bs { result[off + j] ^= x[j]; }
            cipher.encrypt_block((&mut result[off..off + bs]).into());
            for j in 0..bs { result[off + j] ^= y[j]; }
            x.copy_from_slice(&result[off..off + bs]);
            y.copy_from_slice(&data[off..off + bs]);
        }
    }

    Ok(result)
}

#[pyfunction]
fn aes_ige_enc(py: Python<'_>, data: Vec<u8>, key: Vec<u8>, iv: Vec<u8>) -> PyResult<Py<PyBytes>> {
    let out = aes_ige_impl(&data, &key, &iv, 1).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &out).into())
}

#[pyfunction]
fn aes_ige_dec(py: Python<'_>, data: Vec<u8>, key: Vec<u8>, iv: Vec<u8>) -> PyResult<Py<PyBytes>> {
    let out = aes_ige_impl(&data, &key, &iv, 0).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &out).into())
}

#[pyfunction]
fn aes_ige_enc_raw(data: Vec<u8>, key: Vec<u8>, iv: Vec<u8>) -> PyResult<Vec<u8>> {
    aes_ige_impl(&data, &key, &iv, 1).map_err(PyValueError::new_err)
}

#[pyfunction]
fn aes_ige_dec_raw(data: Vec<u8>, key: Vec<u8>, iv: Vec<u8>) -> PyResult<Vec<u8>> {
    aes_ige_impl(&data, &key, &iv, 0).map_err(PyValueError::new_err)
}

#[pyfunction]
fn aes_gcm_encrypt(py: Python<'_>, key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> PyResult<Py<PyBytes>> {
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| PyRuntimeError::new_err(format!("AES-GCM key error: {}", e)))?;
    let n = Nonce::from_slice(&nonce);
    let ct = cipher.encrypt(n, Payload { msg: &plaintext, aad: &aad })
        .map_err(|e| PyRuntimeError::new_err(format!("AES-GCM encrypt error: {}", e)))?;
    Ok(PyBytes::new(py, &ct).into())
}

#[pyfunction]
fn aes_gcm_decrypt(py: Python<'_>, key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> PyResult<Py<PyBytes>> {
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| PyRuntimeError::new_err(format!("AES-GCM key error: {}", e)))?;
    let n = Nonce::from_slice(&nonce);
    let pt = cipher.decrypt(n, Payload { msg: &ciphertext, aad: &aad })
        .map_err(|e| PyRuntimeError::new_err(format!("AES-GCM decrypt error: {}", e)))?;
    Ok(PyBytes::new(py, &pt).into())
}

#[pyfunction]
fn cut(py: Python<'_>, data: Vec<u8>, offset: usize, length: usize) -> PyResult<Py<PyBytes>> {
    if offset > data.len() { return Err(PyValueError::new_err("offset out of range")); }
    let end = offset + length.min(data.len() - offset);
    Ok(PyBytes::new(py, &data[offset..end]).into())
}

#[pyfunction]
fn pack(py: Python<'_>, parts: Vec<Vec<u8>>) -> PyResult<Py<PyBytes>> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&p);
    }
    Ok(PyBytes::new(py, &out).into())
}

#[pymodule]
fn ext(m: &PyModule) -> PyResult<()> {
    apply_bootstrap();
    m.add_function(wrap_pyfunction!(load_schema, m)?)?;
    m.add_function(wrap_pyfunction!(schema_info, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_method, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_constructor, m)?)?;
    m.add_function(wrap_pyfunction!(deserialize_constructor, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ige_enc, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ige_dec, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ige_enc_raw, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ige_dec_raw, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cut, m)?)?;
    m.add_function(wrap_pyfunction!(pack, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::aes_ige_impl;

    #[test]
    fn ige_roundtrip() {
        let key = [0u8; 32];
        let iv = [1u8; 32];
        let plain = [42u8; 64];
        let enc = aes_ige_impl(&plain, &key, &iv, 1).unwrap();
        let dec = aes_ige_impl(&enc, &key, &iv, 0).unwrap();
        assert_eq!(&dec, &plain);
    }
}
