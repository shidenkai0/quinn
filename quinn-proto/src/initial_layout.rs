//! Frame layout of a client's first flight of Initial packets
//!
//! By default a client sends its ClientHello as one in-order CRYPTO frame per Initial packet,
//! followed by PADDING. Some implementations lay out that first flight differently, for example
//! splitting and reordering CRYPTO frames, inserting PING frames and spreading PADDING between
//! frames. An [`InitialLayout`] lets an application choose the layout of the first flight.

use std::fmt;

use crate::{VarInt, coding::BufMutExt, frame::FrameType};

/// A frame in a planned client Initial packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialFrame {
    /// A CRYPTO frame carrying `len` bytes of the CRYPTO stream starting at `offset`
    Crypto {
        /// Offset into the CRYPTO stream
        offset: u64,
        /// Number of CRYPTO bytes carried
        len: u64,
    },
    /// A PING frame
    Ping,
    /// A run of `n` PADDING frames (`n` zero bytes)
    Padding(usize),
}

impl InitialFrame {
    /// Number of bytes the frame occupies in a packet
    pub fn encoded_len(&self) -> usize {
        match *self {
            Self::Crypto { offset, len } => {
                1 + VarInt::from_u64(offset).map_or(8, VarInt::size)
                    + VarInt::from_u64(len).map_or(8, VarInt::size)
                    + len as usize
            }
            Self::Ping => 1,
            Self::Padding(n) => n,
        }
    }

    /// Write the frame, except a CRYPTO frame's data
    pub(crate) fn encode_header(&self, buf: &mut Vec<u8>) {
        match *self {
            Self::Crypto { offset, len } => {
                buf.write(FrameType::CRYPTO);
                buf.write_var(offset);
                buf.write_var(len);
            }
            Self::Ping => buf.write(FrameType::PING),
            Self::Padding(n) => buf.resize(buf.len() + n, 0),
        }
    }
}

/// Chooses the frame layout of a client's first flight of Initial packets
///
/// Only the first transmission of the first flight is affected; retransmissions, ACKs and later
/// Initial packets use the default layout.
pub trait InitialLayout: Send + Sync + fmt::Debug {
    /// Plan the packets carrying the first `crypto_len` bytes of the CRYPTO stream
    ///
    /// `frame_space(i)` is the exact number of bytes available for frames in the `i`th packet of
    /// the flight; space a packet leaves unused is filled with trailing PADDING. Returns the frames
    /// of each packet in wire order, or `None` for the default layout. The CRYPTO frames of a
    /// valid plan cover `0..crypto_len` exactly once; an invalid plan is ignored.
    fn plan(
        &self,
        crypto_len: u64,
        frame_space: &dyn Fn(usize) -> usize,
    ) -> Option<Vec<Vec<InitialFrame>>>;
}

/// Whether `plan` covers `0..crypto_len` exactly once and every packet fits its frame space
pub(crate) fn validate(
    plan: &[Vec<InitialFrame>],
    crypto_len: u64,
    frame_space: &dyn Fn(usize) -> usize,
) -> bool {
    let mut ranges = Vec::new();
    for (i, packet) in plan.iter().enumerate() {
        if packet.is_empty() {
            return false;
        }
        let size: usize = packet.iter().map(InitialFrame::encoded_len).sum();
        if size > frame_space(i) {
            return false;
        }
        for frame in packet {
            if let InitialFrame::Crypto { offset, len } = *frame {
                if len == 0 || VarInt::from_u64(offset + len).is_err() {
                    return false;
                }
                ranges.push((offset, offset + len));
            }
        }
    }
    ranges.sort_unstable();
    let mut next = 0;
    for (start, end) in ranges {
        if start != next {
            return false;
        }
        next = end;
    }
    next == crypto_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_len() {
        assert_eq!(InitialFrame::Ping.encoded_len(), 1);
        assert_eq!(InitialFrame::Padding(7).encoded_len(), 7);
        let crypto = InitialFrame::Crypto {
            offset: 63,
            len: 64,
        };
        assert_eq!(crypto.encoded_len(), 1 + 1 + 2 + 64);
        let mut buf = Vec::new();
        crypto.encode_header(&mut buf);
        assert_eq!(buf, [0x06, 63, 0x40, 64]);
    }

    #[test]
    fn validation() {
        let space = |_| 100;
        let crypto = |offset, len| InitialFrame::Crypto { offset, len };
        assert!(validate(
            &[vec![crypto(10, 20), InitialFrame::Ping, crypto(0, 10)]],
            30,
            &space
        ));
        assert!(validate(
            &[vec![crypto(20, 10)], vec![crypto(0, 20)]],
            30,
            &space
        ));
        // A gap, an overlap, short coverage, an oversized packet, an empty packet
        assert!(!validate(
            &[vec![crypto(0, 10), crypto(11, 19)]],
            30,
            &space
        ));
        assert!(!validate(
            &[vec![crypto(0, 20), crypto(10, 20)]],
            30,
            &space
        ));
        assert!(!validate(&[vec![crypto(0, 20)]], 30, &space));
        assert!(!validate(
            &[vec![crypto(0, 30), InitialFrame::Padding(70)]],
            30,
            &space
        ));
        assert!(!validate(&[vec![crypto(0, 30)], vec![]], 30, &space));
    }
}
