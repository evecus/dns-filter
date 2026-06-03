//! Minimal DNS wire-format encoder/decoder.
//! Supports only what we need: parsing queries, building responses.
//! RFC 1035 compliant for A/AAAA/CNAME queries.

use std::fmt;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct DnsError(pub String);
impl fmt::Display for DnsError { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "DNS: {}", self.0) } }
impl std::error::Error for DnsError {}

pub type DnsResult<T> = Result<T, DnsError>;

macro_rules! dns_err {
    ($($t:tt)*) => { DnsError(format!($($t)*)) }
}

// ── Constants ────────────────────────────────────────────────────────────────

pub mod rcode { pub const NO_ERROR: u16 = 0; pub const NX_DOMAIN: u16 = 3; pub const REFUSED: u16 = 5; pub const SERV_FAIL: u16 = 2; }
pub mod qtype { pub const A: u16 = 1; pub const CNAME: u16 = 5; pub const AAAA: u16 = 28; }
pub const CLASS_IN: u16 = 1;

// ── DNS Message ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,   // lowercase FQDN without trailing dot
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

#[derive(Debug, Clone)]
pub enum RData {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Cname(String),
    Raw(Vec<u8>),
}

impl DnsMessage {
    /// Parse a raw DNS packet
    pub fn parse(buf: &[u8]) -> DnsResult<Self> {
        if buf.len() < 12 {
            return Err(dns_err!("packet too short"));
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
        let arcount = u16::from_be_bytes([buf[10], buf[11]]) as usize;

        let mut pos = 12usize;

        let mut questions = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let (name, new_pos) = parse_name(buf, pos)?;
            pos = new_pos;
            if pos + 4 > buf.len() { return Err(dns_err!("truncated question")); }
            let qtype  = u16::from_be_bytes([buf[pos], buf[pos+1]]);
            let qclass = u16::from_be_bytes([buf[pos+2], buf[pos+3]]);
            pos += 4;
            questions.push(Question { name, qtype, qclass });
        }

        let mut answers = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            let (rr, new_pos) = parse_rr(buf, pos)?;
            pos = new_pos;
            answers.push(rr);
        }
        let mut authorities = Vec::with_capacity(nscount);
        for _ in 0..nscount {
            let (rr, new_pos) = parse_rr(buf, pos)?;
            pos = new_pos;
            authorities.push(rr);
        }
        // skip additionals for brevity
        let _ = arcount;

        Ok(Self { id, flags, questions, answers, authorities, additionals: vec![] })
    }

    /// Is this a standard query (QR=0, OPCODE=0)?
    pub fn is_query(&self) -> bool {
        (self.flags >> 15) == 0 && ((self.flags >> 11) & 0xf) == 0
    }

    /// Serialize to wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

        for q in &self.questions {
            encode_name(&mut buf, &q.name);
            buf.extend_from_slice(&q.qtype.to_be_bytes());
            buf.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for rr in &self.answers {
            encode_rr(&mut buf, rr);
        }
        for rr in &self.authorities {
            encode_rr(&mut buf, rr);
        }
        buf
    }

    // ── Response builders ────────────────────────────────────────────────────

    /// Build a response with RCODE, copying questions from self
    pub fn make_response(&self, rcode: u16) -> Self {
        Self {
            id: self.id,
            // QR=1, AA=0, TC=0, RD=copy, RA=1, RCODE
            flags: 0x8000 | (self.flags & 0x0100) | 0x0080 | rcode,
            questions: self.questions.clone(),
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    pub fn nxdomain(&self) -> Vec<u8> {
        self.make_response(rcode::NX_DOMAIN).to_bytes()
    }

    pub fn refused(&self) -> Vec<u8> {
        self.make_response(rcode::REFUSED).to_bytes()
    }

    pub fn servfail(&self) -> Vec<u8> {
        self.make_response(rcode::SERV_FAIL).to_bytes()
    }

    /// Build a zero-IP response (A=0.0.0.0, AAAA=::)
    pub fn zero_ip(&self, ttl: u32) -> Vec<u8> {
        let mut resp = self.make_response(rcode::NO_ERROR);
        if let Some(q) = self.questions.first() {
            match q.qtype {
                qtype::A => resp.answers.push(ResourceRecord {
                    name: q.name.clone(),
                    rtype: qtype::A,
                    rclass: CLASS_IN,
                    ttl,
                    rdata: RData::A([0, 0, 0, 0]),
                }),
                qtype::AAAA => resp.answers.push(ResourceRecord {
                    name: q.name.clone(),
                    rtype: qtype::AAAA,
                    rclass: CLASS_IN,
                    ttl,
                    rdata: RData::Aaaa([0u8; 16]),
                }),
                _ => {}
            }
        }
        resp.to_bytes()
    }

    /// Patch query ID in a raw response buffer
    pub fn patch_id(buf: &mut [u8], id: u16) {
        if buf.len() >= 2 {
            let b = id.to_be_bytes();
            buf[0] = b[0];
            buf[1] = b[1];
        }
    }

    /// Build rewrite response
    pub fn rewrite(&self, target: &str, ttl: u32) -> Vec<u8> {
        let mut resp = self.make_response(rcode::NO_ERROR);
        if let Some(q) = self.questions.first() {
            let rr = if let Ok(ip4) = target.parse::<std::net::Ipv4Addr>() {
                ResourceRecord { name: q.name.clone(), rtype: qtype::A,    rclass: CLASS_IN, ttl, rdata: RData::A(ip4.octets()) }
            } else if let Ok(ip6) = target.parse::<std::net::Ipv6Addr>() {
                ResourceRecord { name: q.name.clone(), rtype: qtype::AAAA, rclass: CLASS_IN, ttl, rdata: RData::Aaaa(ip6.octets()) }
            } else {
                ResourceRecord { name: q.name.clone(), rtype: qtype::CNAME, rclass: CLASS_IN, ttl, rdata: RData::Cname(target.to_string()) }
            };
            resp.answers.push(rr);
        }
        resp.to_bytes()
    }

    /// Extract minimum TTL from answers (for cache)
    pub fn min_ttl(buf: &[u8]) -> Option<u32> {
        let msg = Self::parse(buf).ok()?;
        msg.answers.iter().map(|r| r.ttl).min().filter(|&t| t > 0)
    }
}

// ── Wire-format helpers ───────────────────────────────────────────────────────

/// Parse a DNS name (with pointer compression support) at `pos`
/// Returns (lowercase FQDN without trailing dot, new_pos)
fn parse_name(buf: &[u8], start: usize) -> DnsResult<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut end_pos = start;
    let mut iterations = 0;

    loop {
        if iterations > 128 { return Err(dns_err!("name compression loop")); }
        iterations += 1;

        if pos >= buf.len() { return Err(dns_err!("name OOB")); }
        let len = buf[pos] as usize;

        if len == 0 {
            if !jumped { end_pos = pos + 1; }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Pointer
            if pos + 1 >= buf.len() { return Err(dns_err!("pointer OOB")); }
            let ptr = (len & 0x3F) << 8 | buf[pos+1] as usize;
            if !jumped { end_pos = pos + 2; }
            jumped = true;
            pos = ptr;
        } else if len & 0xC0 == 0 {
            pos += 1;
            if pos + len > buf.len() { return Err(dns_err!("label OOB")); }
            let label = std::str::from_utf8(&buf[pos..pos+len])
                .map_err(|_| dns_err!("invalid UTF-8 label"))?
                .to_lowercase();
            labels.push(label);
            pos += len;
        } else {
            return Err(dns_err!("unsupported label type {:#x}", len));
        }
    }

    Ok((labels.join("."), end_pos))
}

fn parse_rr(buf: &[u8], pos: usize) -> DnsResult<(ResourceRecord, usize)> {
    let (name, mut pos) = parse_name(buf, pos)?;
    if pos + 10 > buf.len() { return Err(dns_err!("RR header truncated")); }
    let rtype  = u16::from_be_bytes([buf[pos],   buf[pos+1]]);
    let rclass = u16::from_be_bytes([buf[pos+2], buf[pos+3]]);
    let ttl    = u32::from_be_bytes([buf[pos+4], buf[pos+5], buf[pos+6], buf[pos+7]]);
    let rdlen  = u16::from_be_bytes([buf[pos+8], buf[pos+9]]) as usize;
    pos += 10;
    if pos + rdlen > buf.len() { return Err(dns_err!("RDATA truncated")); }
    let rdata_raw = &buf[pos..pos+rdlen];
    let rdata = match rtype {
        qtype::A if rdlen == 4 => RData::A([rdata_raw[0], rdata_raw[1], rdata_raw[2], rdata_raw[3]]),
        qtype::AAAA if rdlen == 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(rdata_raw);
            RData::Aaaa(a)
        }
        qtype::CNAME => {
            let (cname, _) = parse_name(buf, pos)?;
            RData::Cname(cname)
        }
        _ => RData::Raw(rdata_raw.to_vec()),
    };
    Ok((ResourceRecord { name, rtype, rclass, ttl, rdata }, pos + rdlen))
}

fn encode_name(buf: &mut Vec<u8>, name: &str) {
    if name.is_empty() {
        buf.push(0);
        return;
    }
    for label in name.split('.') {
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0);
}

fn encode_rr(buf: &mut Vec<u8>, rr: &ResourceRecord) {
    encode_name(buf, &rr.name);
    buf.extend_from_slice(&rr.rtype.to_be_bytes());
    buf.extend_from_slice(&rr.rclass.to_be_bytes());
    buf.extend_from_slice(&rr.ttl.to_be_bytes());
    // RDATA
    let rdata_start = buf.len();
    buf.push(0); buf.push(0); // rdlength placeholder
    match &rr.rdata {
        RData::A(ip) => buf.extend_from_slice(ip),
        RData::Aaaa(ip) => buf.extend_from_slice(ip),
        RData::Cname(name) => encode_name(buf, name),
        RData::Raw(r) => buf.extend_from_slice(r),
    }
    let rdlen = (buf.len() - rdata_start - 2) as u16;
    let b = rdlen.to_be_bytes();
    buf[rdata_start]   = b[0];
    buf[rdata_start+1] = b[1];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_nxdomain() {
        // Build a fake query
        let q = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: QR=0 RD=1
            0x00, 0x01, // qdcount=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar
            // question: example.com A IN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0,          // end
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ];
        let msg = DnsMessage::parse(&q).unwrap();
        assert!(msg.is_query());
        assert_eq!(msg.questions[0].name, "example.com");
        let resp = msg.nxdomain();
        let resp_msg = DnsMessage::parse(&resp).unwrap();
        assert_eq!(resp_msg.id, 0x1234);
        assert_eq!(resp_msg.flags & 0x000f, 3); // NXDOMAIN
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    fn make_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        buf.extend_from_slice(&[0,0, 0,0, 0,0]);   // an/ns/ar
        // Encode name
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf
    }

    #[test]
    fn test_parse_query() {
        let raw = make_query(0xABCD, "www.example.com", qtype::A);
        let msg = DnsMessage::parse(&raw).unwrap();
        assert_eq!(msg.id, 0xABCD);
        assert!(msg.is_query());
        assert_eq!(msg.questions[0].name, "www.example.com");
        assert_eq!(msg.questions[0].qtype, qtype::A);
    }

    #[test]
    fn test_zero_ip_a() {
        let raw = make_query(1, "ads.com", qtype::A);
        let msg = DnsMessage::parse(&raw).unwrap();
        let resp = msg.zero_ip(60);
        let parsed = DnsMessage::parse(&resp).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert!(matches!(parsed.answers[0].rdata, RData::A([0,0,0,0])));
    }

    #[test]
    fn test_rewrite_ipv4() {
        let raw = make_query(2, "test.com", qtype::A);
        let msg = DnsMessage::parse(&raw).unwrap();
        let resp = msg.rewrite("1.2.3.4", 300);
        let parsed = DnsMessage::parse(&resp).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert!(matches!(parsed.answers[0].rdata, RData::A([1,2,3,4])));
    }

    #[test]
    fn test_patch_id() {
        let raw = make_query(0x1111, "test.com", qtype::A);
        let msg = DnsMessage::parse(&raw).unwrap();
        let mut resp = msg.nxdomain();
        DnsMessage::patch_id(&mut resp, 0x9999);
        let patched = DnsMessage::parse(&resp).unwrap();
        assert_eq!(patched.id, 0x9999);
    }

    #[test]
    fn test_multi_label_domain() {
        let raw = make_query(3, "a.b.c.d.example.co.uk", qtype::AAAA);
        let msg = DnsMessage::parse(&raw).unwrap();
        assert_eq!(msg.questions[0].name, "a.b.c.d.example.co.uk");
        assert_eq!(msg.questions[0].qtype, qtype::AAAA);
    }
}
