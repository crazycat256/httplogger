use std::fmt;

pub const EXT_STATUS_REQUEST: u16 = 0x0005;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_SCT: u16 = 0x0012;
pub const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXT_KEY_SHARE: u16 = 0x0033;
pub const EXT_ALPS_OLD: u16 = 0x4469;
pub const EXT_ALPS_NEW: u16 = 0x44cd;
pub const EXT_ECH: u16 = 0xfe0d;

const CERT_COMPRESSION_BROTLI: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub alpn: Vec<Vec<u8>>,
    pub key_share_groups: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub cert_compression: Vec<u16>,
}

impl ClientHelloInfo {
    pub fn grease(&self) -> bool {
        self.cipher_suites.iter().any(|id| is_grease(*id))
            || self.extensions.iter().any(|id| is_grease(*id))
            || self.groups.iter().any(|id| is_grease(*id))
    }

    pub fn has_ocsp(&self) -> bool {
        self.extensions.contains(&EXT_STATUS_REQUEST)
    }

    pub fn has_sct(&self) -> bool {
        self.extensions.contains(&EXT_SCT)
    }

    pub fn has_ech(&self) -> bool {
        self.extensions.contains(&EXT_ECH)
    }

    pub fn has_brotli_cert(&self) -> bool {
        self.cert_compression.contains(&CERT_COMPRESSION_BROTLI)
    }

    pub fn alps_new_codepoint(&self) -> Option<bool> {
        if self.extensions.contains(&EXT_ALPS_OLD) {
            Some(false)
        } else if self.extensions.contains(&EXT_ALPS_NEW) {
            Some(true)
        } else {
            None
        }
    }

    pub fn identity_key(&self) -> String {
        format!(
            "c:{}|e:{}|g:{}|s:{}|a:{}|k:{}|v:{}|z:{}",
            join_hex(without_grease(&self.cipher_suites)),
            join_hex(sorted_without_grease(&self.extensions)),
            join_hex(without_grease(&self.groups)),
            join_hex(without_grease(&self.signature_algorithms)),
            self.alpn
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>()
                .join(","),
            join_hex(without_grease(&self.key_share_groups)),
            join_hex(without_grease(&self.supported_versions)),
            join_hex(self.cert_compression.clone()),
        )
    }

    pub fn summary(&self) -> String {
        format!(
            "ciphers={} ext={} groups={} sigalgs={} alpn=[{}] shares={} grease={} ech={} alps={:?}",
            without_grease(&self.cipher_suites).len(),
            without_grease(&self.extensions).len(),
            without_grease(&self.groups).len(),
            without_grease(&self.signature_algorithms).len(),
            self.alpn
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>()
                .join(","),
            join_hex(without_grease(&self.key_share_groups)),
            self.grease(),
            self.has_ech(),
            self.alps_new_codepoint(),
        )
    }
}

#[cfg(test)]
pub fn compare_hellos(inbound: &ClientHelloInfo, outbound: &ClientHelloInfo) -> Vec<String> {
    let mut diffs = Vec::new();
    diff_set(
        "ciphers",
        &inbound.cipher_suites,
        &outbound.cipher_suites,
        &mut diffs,
    );
    diff_set(
        "extensions",
        &inbound.extensions,
        &outbound.extensions,
        &mut diffs,
    );
    diff_set("groups", &inbound.groups, &outbound.groups, &mut diffs);
    diff_set(
        "sigalgs",
        &inbound.signature_algorithms,
        &outbound.signature_algorithms,
        &mut diffs,
    );
    diff_set(
        "key_share",
        &inbound.key_share_groups,
        &outbound.key_share_groups,
        &mut diffs,
    );
    diff_set(
        "supported_versions",
        &inbound.supported_versions,
        &outbound.supported_versions,
        &mut diffs,
    );
    diff_set(
        "cert_compression",
        &inbound.cert_compression,
        &outbound.cert_compression,
        &mut diffs,
    );
    if inbound.alpn != outbound.alpn {
        diffs.push(format!(
            "alpn inbound={:?} outbound={:?}",
            inbound
                .alpn
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>(),
            outbound
                .alpn
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>(),
        ));
    }
    for (name, a, b) in [
        ("grease", inbound.grease(), outbound.grease()),
        ("ech", inbound.has_ech(), outbound.has_ech()),
        ("ocsp", inbound.has_ocsp(), outbound.has_ocsp()),
        ("sct", inbound.has_sct(), outbound.has_sct()),
        (
            "brotli_cert",
            inbound.has_brotli_cert(),
            outbound.has_brotli_cert(),
        ),
    ] {
        if a != b {
            diffs.push(format!("{name}: inbound={a} outbound={b}"));
        }
    }
    if inbound.alps_new_codepoint() != outbound.alps_new_codepoint() {
        diffs.push(format!(
            "alps: inbound={:?} outbound={:?}",
            inbound.alps_new_codepoint(),
            outbound.alps_new_codepoint()
        ));
    }
    diffs
}

impl fmt::Display for ClientHelloInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

pub fn is_grease(id: u16) -> bool {
    id & 0x0f0f == 0x0a0a
}

pub fn without_grease(ids: &[u16]) -> Vec<u16> {
    ids.iter().copied().filter(|id| !is_grease(*id)).collect()
}

fn sorted_without_grease(ids: &[u16]) -> Vec<u16> {
    let mut ids = without_grease(ids);
    ids.sort_unstable();
    ids
}

pub fn join_hex(ids: Vec<u16>) -> String {
    ids.iter()
        .map(|id| format!("{id:04x}"))
        .collect::<Vec<_>>()
        .join("-")
}

pub fn alpn_wire(protocols: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for proto in protocols {
        out.push(proto.len() as u8);
        out.extend_from_slice(proto);
    }
    out
}

/// Pull TLS records from `buf` until a complete ClientHello is parsed.
/// Returns the hello and how many leading bytes of `buf` were consumed.
pub fn extract_client_hello(buf: &[u8]) -> Option<(ClientHelloInfo, usize)> {
    let mut handshake = Vec::new();
    let mut offset = 0;
    while offset + 5 <= buf.len() {
        if buf[offset] != 0x16 {
            return None;
        }
        let record_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        let record_end = offset + 5 + record_len;
        if record_end > buf.len() {
            return None;
        }
        handshake.extend_from_slice(&buf[offset + 5..record_end]);
        offset = record_end;
        if let Some(hello) = parse_handshake_client_hello(&handshake) {
            return Some((hello, offset));
        }
    }
    None
}

fn parse_handshake_client_hello(handshake: &[u8]) -> Option<ClientHelloInfo> {
    if handshake.len() < 4 {
        return None;
    }
    if handshake[0] != 0x01 {
        return None;
    }
    let hello_len = u24(&handshake[1..4])?;
    let body_end = 4 + hello_len;
    if handshake.len() < body_end {
        return None;
    }
    parse_client_hello_body(&handshake[4..body_end])
}

fn parse_client_hello_body(body: &[u8]) -> Option<ClientHelloInfo> {
    if body.len() < 34 {
        return None;
    }
    let mut pos = 34;
    let session_id_len = *body.get(pos)? as usize;
    pos += 1 + session_id_len;

    let cipher_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 2;
    let cipher_suites = read_u16_list(body.get(pos..pos + cipher_len)?)?;
    pos += cipher_len;

    let compression_len = *body.get(pos)? as usize;
    pos += 1 + compression_len;
    if pos + 2 > body.len() {
        return None;
    }

    let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_bytes = body.get(pos..pos + ext_len)?;

    let mut extensions = Vec::new();
    let mut groups = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut alpn = Vec::new();
    let mut key_share_groups = Vec::new();
    let mut supported_versions = Vec::new();
    let mut cert_compression = Vec::new();

    let mut ext_pos = 0;
    while ext_pos + 4 <= ext_bytes.len() {
        let ext_type = u16::from_be_bytes([ext_bytes[ext_pos], ext_bytes[ext_pos + 1]]);
        let len = u16::from_be_bytes([ext_bytes[ext_pos + 2], ext_bytes[ext_pos + 3]]) as usize;
        ext_pos += 4;
        let data = ext_bytes.get(ext_pos..ext_pos + len)?;
        ext_pos += len;
        extensions.push(ext_type);
        match ext_type {
            EXT_SUPPORTED_GROUPS => groups = parse_u16_vector(data).unwrap_or_default(),
            EXT_SIGNATURE_ALGORITHMS => {
                signature_algorithms = parse_u16_vector(data).unwrap_or_default();
            }
            EXT_ALPN => alpn = parse_alpn(data).unwrap_or_default(),
            EXT_KEY_SHARE => key_share_groups = parse_key_share_groups(data).unwrap_or_default(),
            EXT_SUPPORTED_VERSIONS => {
                supported_versions = parse_supported_versions(data).unwrap_or_default();
            }
            EXT_COMPRESS_CERTIFICATE => {
                cert_compression = parse_cert_compression(data).unwrap_or_default();
            }
            _ => {}
        }
    }

    Some(ClientHelloInfo {
        cipher_suites,
        extensions,
        groups,
        signature_algorithms,
        alpn,
        key_share_groups,
        supported_versions,
        cert_compression,
    })
}

fn parse_u16_vector(data: &[u8]) -> Option<Vec<u16>> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    read_u16_list(data.get(2..2 + len)?)
}

fn parse_alpn(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut rest = data.get(2..2 + len)?;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let n = rest[0] as usize;
        rest = rest.get(1..)?;
        out.push(rest.get(..n)?.to_vec());
        rest = rest.get(n..)?;
    }
    Some(out)
}

fn parse_key_share_groups(data: &[u8]) -> Option<Vec<u16>> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut rest = data.get(2..2 + len)?;
    let mut groups = Vec::new();
    while rest.len() >= 4 {
        let group = u16::from_be_bytes([rest[0], rest[1]]);
        let key_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        rest = rest.get(4 + key_len..)?;
        groups.push(group);
    }
    Some(groups)
}

fn parse_supported_versions(data: &[u8]) -> Option<Vec<u16>> {
    if data.is_empty() {
        return None;
    }
    let len = data[0] as usize;
    read_u16_list(data.get(1..1 + len)?)
}

fn parse_cert_compression(data: &[u8]) -> Option<Vec<u16>> {
    if data.is_empty() {
        return None;
    }
    let len = data[0] as usize;
    read_u16_list(data.get(1..1 + len)?)
}

fn read_u16_list(data: &[u8]) -> Option<Vec<u16>> {
    if data.len() % 2 != 0 {
        return None;
    }
    Some(
        data.chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect(),
    )
}

fn u24(bytes: &[u8]) -> Option<usize> {
    Some(
        ((bytes.first().copied()? as usize) << 16)
            | ((bytes.get(1).copied()? as usize) << 8)
            | (bytes.get(2).copied()? as usize),
    )
}

#[cfg(test)]
fn diff_set(name: &str, inbound: &[u16], outbound: &[u16], diffs: &mut Vec<String>) {
    use std::collections::BTreeSet;
    let a: BTreeSet<u16> = without_grease(inbound).into_iter().collect();
    let b: BTreeSet<u16> = without_grease(outbound).into_iter().collect();
    let missing: Vec<_> = a.difference(&b).map(|id| format!("{id:04x}")).collect();
    let extra: Vec<_> = b.difference(&a).map(|id| format!("{id:04x}")).collect();
    if !missing.is_empty() || !extra.is_empty() {
        diffs.push(format!(
            "{name}: missing_outbound={} extra_outbound={}",
            missing.join(","),
            extra.join(",")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        let ciphers: [u16; 4] = [0x1301, 0x1302, 0xc02f, 0x0a0a];
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.push(1);
        body.push(0);

        let mut exts = Vec::new();
        push_ext(&mut exts, EXT_SUPPORTED_GROUPS, &{
            let mut d = Vec::new();
            let groups: [u16; 2] = [0x11ec, 0x001d];
            d.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
            for g in groups {
                d.extend_from_slice(&g.to_be_bytes());
            }
            d
        });
        push_ext(&mut exts, EXT_ALPN, &{
            let mut d = Vec::new();
            let proto = alpn_wire(&[b"h2".to_vec(), b"http/1.1".to_vec()]);
            d.extend_from_slice(&(proto.len() as u16).to_be_bytes());
            d.extend_from_slice(&proto);
            d
        });
        push_ext(&mut exts, EXT_ECH, &[]);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.push(((body.len() >> 16) & 0xff) as u8);
        handshake.push(((body.len() >> 8) & 0xff) as u8);
        handshake.push((body.len() & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn push_ext(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
        out.extend_from_slice(&ext_type.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    #[test]
    fn parses_client_hello_record() {
        let raw = build_hello();
        let (hello, consumed) = extract_client_hello(&raw).expect("hello");
        assert_eq!(consumed, raw.len());
        assert_eq!(hello.cipher_suites, vec![0x1301, 0x1302, 0xc02f, 0x0a0a]);
        assert!(hello.grease());
        assert!(hello.has_ech());
        assert_eq!(hello.groups, vec![0x11ec, 0x001d]);
        assert_eq!(hello.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }
}
