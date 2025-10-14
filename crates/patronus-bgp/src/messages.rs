// BGP-4 Message Encoding/Decoding (RFC 4271)
//
// BGP messages have a common header followed by type-specific data.
// This module implements encoding and decoding for all BGP message types.

use crate::error::{BgpError, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr};

/// BGP Message Types (RFC 4271 Section 4.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
}

impl TryFrom<u8> for MessageType {
    type Error = BgpError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(MessageType::Open),
            2 => Ok(MessageType::Update),
            3 => Ok(MessageType::Notification),
            4 => Ok(MessageType::Keepalive),
            _ => Err(BgpError::ProtocolError(format!("Invalid message type: {}", value))),
        }
    }
}

/// BGP Message Header (RFC 4271 Section 4.1)
/// All BGP messages start with a 19-byte header
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// Marker (16 bytes, all ones for unauthenticated messages)
    pub marker: [u8; 16],
    /// Length (2 bytes, total message length including header)
    pub length: u16,
    /// Type (1 byte)
    pub msg_type: MessageType,
}

impl MessageHeader {
    /// Minimum BGP message size (header only)
    pub const MIN_SIZE: usize = 19;

    /// Maximum BGP message size
    pub const MAX_SIZE: usize = 4096;

    /// Create a new message header
    pub fn new(msg_type: MessageType, length: u16) -> Self {
        Self {
            marker: [0xFF; 16], // All ones marker
            length,
            msg_type,
        }
    }

    /// Encode header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.marker);
        buf.put_u16(self.length);
        buf.put_u8(self.msg_type as u8);
    }

    /// Decode header from bytes
    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < Self::MIN_SIZE {
            return Err(BgpError::ParseError("Insufficient data for header".into()));
        }

        let mut marker = [0u8; 16];
        buf.copy_to_slice(&mut marker);

        let length = buf.get_u16();
        let msg_type = MessageType::try_from(buf.get_u8())?;

        // Validate marker (should be all ones)
        if marker != [0xFF; 16] {
            return Err(BgpError::ProtocolError("Invalid marker".into()));
        }

        // Validate length
        if length < Self::MIN_SIZE as u16 || length > Self::MAX_SIZE as u16 {
            return Err(BgpError::ProtocolError(format!("Invalid length: {}", length)));
        }

        Ok(Self {
            marker,
            length,
            msg_type,
        })
    }
}

/// BGP OPEN Message (RFC 4271 Section 4.2)
#[derive(Debug, Clone)]
pub struct OpenMessage {
    /// BGP version (should be 4)
    pub version: u8,
    /// My Autonomous System number
    pub my_asn: u16,
    /// Hold Time (in seconds)
    pub hold_time: u16,
    /// BGP Identifier (router ID)
    pub bgp_identifier: u32,
    /// Optional Parameters
    pub opt_params: Vec<OptionalParameter>,
}

impl OpenMessage {
    /// Create a new OPEN message
    pub fn new(my_asn: u16, hold_time: u16, bgp_identifier: u32) -> Self {
        Self {
            version: 4,
            my_asn,
            hold_time,
            bgp_identifier,
            opt_params: Vec::new(),
        }
    }

    /// Encode OPEN message
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        // Calculate optional parameters length
        let opt_param_len: usize = self.opt_params.iter().map(|p| p.encoded_len()).sum();

        // Calculate total message length
        let msg_len = MessageHeader::MIN_SIZE + 10 + opt_param_len;

        // Encode header
        let header = MessageHeader::new(MessageType::Open, msg_len as u16);
        header.encode(&mut buf);

        // Encode OPEN message data
        buf.put_u8(self.version);
        buf.put_u16(self.my_asn);
        buf.put_u16(self.hold_time);
        buf.put_u32(self.bgp_identifier);
        buf.put_u8(opt_param_len as u8);

        // Encode optional parameters
        for param in &self.opt_params {
            param.encode(&mut buf);
        }

        buf.freeze()
    }

    /// Decode OPEN message
    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 10 {
            return Err(BgpError::ParseError("Insufficient data for OPEN message".into()));
        }

        let version = buf.get_u8();
        if version != 4 {
            return Err(BgpError::ProtocolError(format!("Unsupported BGP version: {}", version)));
        }

        let my_asn = buf.get_u16();
        let hold_time = buf.get_u16();
        let bgp_identifier = buf.get_u32();
        let opt_param_len = buf.get_u8() as usize;

        // Decode optional parameters
        let mut opt_params = Vec::new();
        let mut remaining = opt_param_len;

        while remaining > 0 {
            let param = OptionalParameter::decode(buf)?;
            remaining -= param.encoded_len();
            opt_params.push(param);
        }

        Ok(Self {
            version,
            my_asn,
            hold_time,
            bgp_identifier,
            opt_params,
        })
    }
}

/// BGP Optional Parameter
#[derive(Debug, Clone)]
pub struct OptionalParameter {
    pub param_type: u8,
    pub value: Vec<u8>,
}

impl OptionalParameter {
    fn encoded_len(&self) -> usize {
        2 + self.value.len()
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.param_type);
        buf.put_u8(self.value.len() as u8);
        buf.put_slice(&self.value);
    }

    fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 2 {
            return Err(BgpError::ParseError("Insufficient data for optional parameter".into()));
        }

        let param_type = buf.get_u8();
        let length = buf.get_u8() as usize;

        if buf.remaining() < length {
            return Err(BgpError::ParseError("Insufficient data for parameter value".into()));
        }

        let mut value = vec![0u8; length];
        buf.copy_to_slice(&mut value);

        Ok(Self { param_type, value })
    }
}

/// BGP KEEPALIVE Message (RFC 4271 Section 4.4)
/// KEEPALIVE messages consist only of the message header
#[derive(Debug, Clone)]
pub struct KeepaliveMessage;

impl KeepaliveMessage {
    /// Encode KEEPALIVE message
    pub fn encode() -> Bytes {
        let mut buf = BytesMut::new();
        let header = MessageHeader::new(MessageType::Keepalive, MessageHeader::MIN_SIZE as u16);
        header.encode(&mut buf);
        buf.freeze()
    }

    /// Decode KEEPALIVE message
    pub fn decode(_buf: &mut Bytes) -> Result<Self> {
        // KEEPALIVE has no additional data beyond the header
        Ok(Self)
    }
}

/// BGP NOTIFICATION Message (RFC 4271 Section 4.5)
#[derive(Debug, Clone)]
pub struct NotificationMessage {
    /// Error code
    pub error_code: u8,
    /// Error subcode
    pub error_subcode: u8,
    /// Data (optional)
    pub data: Vec<u8>,
}

impl NotificationMessage {
    /// Create a new NOTIFICATION message
    pub fn new(error_code: u8, error_subcode: u8) -> Self {
        Self {
            error_code,
            error_subcode,
            data: Vec::new(),
        }
    }

    /// Encode NOTIFICATION message
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        let msg_len = MessageHeader::MIN_SIZE + 2 + self.data.len();
        let header = MessageHeader::new(MessageType::Notification, msg_len as u16);
        header.encode(&mut buf);

        buf.put_u8(self.error_code);
        buf.put_u8(self.error_subcode);
        buf.put_slice(&self.data);

        buf.freeze()
    }

    /// Decode NOTIFICATION message
    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 2 {
            return Err(BgpError::ParseError("Insufficient data for NOTIFICATION".into()));
        }

        let error_code = buf.get_u8();
        let error_subcode = buf.get_u8();

        let mut data = Vec::new();
        if buf.has_remaining() {
            data = buf.to_vec();
        }

        Ok(Self {
            error_code,
            error_subcode,
            data,
        })
    }
}

/// BGP UPDATE Message (RFC 4271 Section 4.3)
/// Simplified implementation - full UPDATE support is complex
#[derive(Debug, Clone)]
pub struct UpdateMessage {
    /// Withdrawn routes
    pub withdrawn_routes: Vec<IpPrefix>,
    /// Path attributes
    pub path_attributes: Vec<PathAttribute>,
    /// Network Layer Reachability Information (NLRI)
    pub nlri: Vec<IpPrefix>,
}

impl UpdateMessage {
    /// Create a new UPDATE message
    pub fn new() -> Self {
        Self {
            withdrawn_routes: Vec::new(),
            path_attributes: Vec::new(),
            nlri: Vec::new(),
        }
    }

    /// Encode UPDATE message
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        // Calculate withdrawn routes length
        let withdrawn_len: usize = self.withdrawn_routes.iter().map(|r| r.encoded_len()).sum();

        // Calculate path attributes length
        let path_attr_len: usize = self.path_attributes.iter().map(|a| a.encoded_len()).sum();

        // Calculate NLRI length
        let nlri_len: usize = self.nlri.iter().map(|n| n.encoded_len()).sum();

        // Calculate total message length
        let msg_len = MessageHeader::MIN_SIZE + 2 + withdrawn_len + 2 + path_attr_len + nlri_len;

        // Encode header
        let header = MessageHeader::new(MessageType::Update, msg_len as u16);
        header.encode(&mut buf);

        // Encode withdrawn routes
        buf.put_u16(withdrawn_len as u16);
        for route in &self.withdrawn_routes {
            route.encode(&mut buf);
        }

        // Encode path attributes
        buf.put_u16(path_attr_len as u16);
        for attr in &self.path_attributes {
            attr.encode(&mut buf);
        }

        // Encode NLRI
        for nlri in &self.nlri {
            nlri.encode(&mut buf);
        }

        buf.freeze()
    }

    /// Decode UPDATE message (simplified)
    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(BgpError::ParseError("Insufficient data for UPDATE".into()));
        }

        // Decode withdrawn routes
        let withdrawn_len = buf.get_u16() as usize;
        let mut withdrawn_routes = Vec::new();
        let mut withdrawn_remaining = withdrawn_len;

        while withdrawn_remaining > 0 {
            let prefix = IpPrefix::decode(buf)?;
            withdrawn_remaining -= prefix.encoded_len();
            withdrawn_routes.push(prefix);
        }

        // Decode path attributes
        let path_attr_len = buf.get_u16() as usize;
        let mut path_attributes = Vec::new();
        let mut attr_remaining = path_attr_len;

        while attr_remaining > 0 {
            let attr = PathAttribute::decode(buf)?;
            attr_remaining -= attr.encoded_len();
            path_attributes.push(attr);
        }

        // Decode NLRI
        let mut nlri = Vec::new();
        while buf.has_remaining() {
            nlri.push(IpPrefix::decode(buf)?);
        }

        Ok(Self {
            withdrawn_routes,
            path_attributes,
            nlri,
        })
    }
}

/// IP Prefix (for NLRI)
#[derive(Debug, Clone)]
pub struct IpPrefix {
    pub prefix_len: u8,
    pub prefix: Vec<u8>,
}

impl IpPrefix {
    fn encoded_len(&self) -> usize {
        1 + ((self.prefix_len as usize + 7) / 8)
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.prefix_len);
        buf.put_slice(&self.prefix);
    }

    fn decode(buf: &mut Bytes) -> Result<Self> {
        if !buf.has_remaining() {
            return Err(BgpError::ParseError("No data for prefix".into()));
        }

        let prefix_len = buf.get_u8();
        let prefix_bytes = (prefix_len as usize + 7) / 8;

        if buf.remaining() < prefix_bytes {
            return Err(BgpError::ParseError("Insufficient data for prefix".into()));
        }

        let mut prefix = vec![0u8; prefix_bytes];
        buf.copy_to_slice(&mut prefix);

        Ok(Self { prefix_len, prefix })
    }
}

/// Path Attribute (simplified)
#[derive(Debug, Clone)]
pub struct PathAttribute {
    pub flags: u8,
    pub type_code: u8,
    pub value: Vec<u8>,
}

impl PathAttribute {
    fn encoded_len(&self) -> usize {
        let extended = (self.flags & 0x10) != 0;
        if extended {
            4 + self.value.len()
        } else {
            3 + self.value.len()
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8(self.type_code);

        let extended = (self.flags & 0x10) != 0;
        if extended {
            buf.put_u16(self.value.len() as u16);
        } else {
            buf.put_u8(self.value.len() as u8);
        }

        buf.put_slice(&self.value);
    }

    fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 3 {
            return Err(BgpError::ParseError("Insufficient data for path attribute".into()));
        }

        let flags = buf.get_u8();
        let type_code = buf.get_u8();

        let extended = (flags & 0x10) != 0;
        let length = if extended {
            if buf.remaining() < 2 {
                return Err(BgpError::ParseError("Insufficient data for extended length".into()));
            }
            buf.get_u16() as usize
        } else {
            buf.get_u8() as usize
        };

        if buf.remaining() < length {
            return Err(BgpError::ParseError("Insufficient data for attribute value".into()));
        }

        let mut value = vec![0u8; length];
        buf.copy_to_slice(&mut value);

        Ok(Self {
            flags,
            type_code,
            value,
        })
    }
}

/// Complete BGP Message
#[derive(Debug, Clone)]
pub enum BgpMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    Notification(NotificationMessage),
    Keepalive(KeepaliveMessage),
}

impl BgpMessage {
    /// Encode a BGP message to bytes
    pub fn encode(&self) -> Bytes {
        match self {
            BgpMessage::Open(msg) => msg.encode(),
            BgpMessage::Update(msg) => msg.encode(),
            BgpMessage::Notification(msg) => msg.encode(),
            BgpMessage::Keepalive(msg) => KeepaliveMessage::encode(),
        }
    }

    /// Decode a BGP message from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut buf = Bytes::copy_from_slice(data);

        // Decode header
        let header = MessageHeader::decode(&mut buf)?;

        // Decode message body based on type
        match header.msg_type {
            MessageType::Open => Ok(BgpMessage::Open(OpenMessage::decode(&mut buf)?)),
            MessageType::Update => Ok(BgpMessage::Update(UpdateMessage::decode(&mut buf)?)),
            MessageType::Notification => Ok(BgpMessage::Notification(NotificationMessage::decode(&mut buf)?)),
            MessageType::Keepalive => Ok(BgpMessage::Keepalive(KeepaliveMessage::decode(&mut buf)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_encode_decode() {
        let keepalive = KeepaliveMessage;
        let bytes = KeepaliveMessage::encode();

        assert_eq!(bytes.len(), MessageHeader::MIN_SIZE);

        let decoded = BgpMessage::decode(&bytes).unwrap();
        assert!(matches!(decoded, BgpMessage::Keepalive(_)));
    }

    #[test]
    fn test_open_encode_decode() {
        let open = OpenMessage::new(65000, 180, 0x01010101);
        let bytes = open.encode();

        let mut buf = Bytes::from(bytes.clone());
        let _header = MessageHeader::decode(&mut buf).unwrap();
        let decoded = OpenMessage::decode(&mut buf).unwrap();

        assert_eq!(decoded.version, 4);
        assert_eq!(decoded.my_asn, 65000);
        assert_eq!(decoded.hold_time, 180);
        assert_eq!(decoded.bgp_identifier, 0x01010101);
    }

    #[test]
    fn test_notification_encode_decode() {
        let notif = NotificationMessage::new(6, 1); // Cease
        let bytes = notif.encode();

        let mut buf = Bytes::from(bytes.clone());
        let _header = MessageHeader::decode(&mut buf).unwrap();
        let decoded = NotificationMessage::decode(&mut buf).unwrap();

        assert_eq!(decoded.error_code, 6);
        assert_eq!(decoded.error_subcode, 1);
    }

    #[test]
    fn test_message_header() {
        let header = MessageHeader::new(MessageType::Keepalive, MessageHeader::MIN_SIZE as u16);

        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = MessageHeader::decode(&mut bytes).unwrap();

        assert_eq!(decoded.length, MessageHeader::MIN_SIZE as u16);
        assert_eq!(decoded.msg_type, MessageType::Keepalive);
    }
}
