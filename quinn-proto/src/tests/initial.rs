//! Client Initial packet knobs: packet numbering, datagram size and first-flight layout

use super::*;
use crate::{
    InitialFrame, InitialLayout,
    crypto::ServerConfig as _,
    frame::{Frame, Iter},
    packet::{FixedLengthConnectionIdParser, PartialDecode},
};

/// A decoded frame, with PADDING runs collapsed
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decoded {
    Crypto { offset: u64, len: u64 },
    Ping,
    Padding(usize),
    Ack,
    Other,
}

/// A decrypted client Initial packet: number, encoded number length, frames
#[derive(Debug)]
struct ClientInitial {
    number: u64,
    number_len: usize,
    frames: Vec<Decoded>,
}

/// Decrypt the client Initial packets of `datagram`, the first datagram of a connection
fn client_initials(datagram: &[u8]) -> Vec<ClientInitial> {
    client_initials_with(datagram, None)
}

/// Decrypt the client Initial packets of `datagram`, with keys from the original destination CID
fn client_initials_with(datagram: &[u8], odcid: Option<ConnectionId>) -> Vec<ClientInitial> {
    let mut packets = Vec::new();
    let mut rest = Some(BytesMut::from(datagram));
    while let Some(data) = rest.take() {
        if data[0] & 0xf0 != 0xc0 {
            // Not a long-header Initial packet
            break;
        }
        let (partial, next) =
            PartialDecode::new(data, &FixedLengthConnectionIdParser::new(0), &[1], false).unwrap();
        rest = next;
        let dst_cid = odcid.unwrap_or(*partial.dst_cid());
        let keys = server_crypto().initial_keys(1, &dst_cid).unwrap();
        let mut packet = partial.finish(Some(&*keys.header.remote)).unwrap();
        let encoded = packet.header.number().unwrap();
        let number = encoded.expand(1);
        keys.packet
            .remote
            .decrypt(number, &packet.header_data, &mut packet.payload)
            .unwrap();
        let mut frames = Vec::new();
        for frame in Iter::new(packet.payload.freeze()).unwrap() {
            let frame = match frame.unwrap() {
                Frame::Padding => {
                    if let Some(Decoded::Padding(n)) = frames.last_mut() {
                        *n += 1;
                        continue;
                    }
                    Decoded::Padding(1)
                }
                Frame::Ping => Decoded::Ping,
                Frame::Crypto(crypto) => Decoded::Crypto {
                    offset: crypto.offset,
                    len: crypto.data.len() as u64,
                },
                Frame::Ack(_) => Decoded::Ack,
                _ => Decoded::Other,
            };
            frames.push(frame);
        }
        packets.push(ClientInitial {
            number,
            number_len: encoded.len(),
            frames,
        });
    }
    packets
}

fn initial_dcid(datagram: &[u8]) -> ConnectionId {
    let (partial, _) = PartialDecode::new(
        BytesMut::from(datagram),
        &FixedLengthConnectionIdParser::new(0),
        &[1],
        false,
    )
    .unwrap();
    *partial.dst_cid()
}

fn is_initial(datagram: &[u8]) -> bool {
    datagram[0] & 0xf0 == 0xc0
}

fn client_config_with(transport: TransportConfig) -> ClientConfig {
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    config
}

/// Drive the handshake to completion, returning every client datagram
fn connect_capturing(pair: &mut Pair, config: ClientConfig) -> (ConnectionHandle, Vec<Bytes>) {
    let client_ch = pair.begin_connect(config);
    let mut datagrams = Vec::new();
    for _ in 0..100 {
        pair.client.drive(pair.time, pair.server.addr);
        datagrams.extend(pair.client.outbound.iter().map(|(_, data)| data.clone()));
        if !pair.step() {
            break;
        }
    }
    let server_ch = pair.server.assert_accept();
    pair.finish_connect(client_ch, server_ch);
    (client_ch, datagrams)
}

#[test]
fn first_packet_number_and_lengths() {
    let _guard = subscribe();
    let mut transport = TransportConfig::default();
    transport
        .initial_packet_number(1)
        .packet_number_lengths(vec![1, 2]);
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_config_with(transport));

    // The first Initial, then its PTO retransmission after dropping it
    pair.client.drive(pair.time, pair.server.addr);
    let first = pair.client.outbound.pop_front().unwrap().1;
    pair.client.outbound.clear();
    pair.time = pair.client.next_wakeup().unwrap();
    pair.client.drive(pair.time, pair.server.addr);
    let second = pair.client.outbound.front().unwrap().1.clone();
    // ... and the next PTO retransmission keeps the last configured length
    pair.client.outbound.clear();
    pair.time = pair.client.next_wakeup().unwrap();
    pair.client.drive(pair.time, pair.server.addr);
    let third = pair.client.outbound.front().unwrap().1.clone();
    let odcid = initial_dcid(&first);
    let first = client_initials_with(&first, Some(odcid));
    let second = client_initials_with(&second, Some(odcid));
    assert_eq!((first[0].number, first[0].number_len), (1, 1));
    assert_eq!((second[0].number, second[0].number_len), (2, 2));
    let third = client_initials_with(&third, Some(odcid));
    assert!(third[0].number >= 3);
    assert_eq!(third[0].number_len, 2);

    pair.drive();
    let server_ch = pair.server.assert_accept();
    pair.finish_connect(client_ch, server_ch);
    // Every space starts at 1
    pair.drive();
    let [initial, handshake, data] = pair.client_conn_mut(client_ch).next_packet_numbers();
    assert!(initial > 2 && handshake > 1 && data > 1);
}

#[test]
fn shared_packet_numbers() {
    let _guard = subscribe();
    let mut transport = TransportConfig::default();
    transport
        .initial_packet_number(1)
        .shared_packet_numbers(true);
    let mut pair = Pair::default();
    let (client_ch, _) = connect_capturing(&mut pair, client_config_with(transport));
    pair.drive();

    // All spaces draw from one counter, so their next numbers agree
    let [initial, handshake, data] = pair.client_conn_mut(client_ch).next_packet_numbers();
    assert!(initial > 2);
    assert_eq!((initial, handshake), (data, data));
}

#[test]
fn exact_initial_datagram_size() {
    let _guard = subscribe();
    for size in [1230u16, 1250] {
        let mut transport = TransportConfig::default();
        transport
            .initial_mtu(1452)
            .mtu_discovery_config(None)
            .initial_datagram_size(Some(size));
        let mut pair = Pair::default();
        let client_ch = pair.begin_connect(client_config_with(transport));

        // The first Initial and two PTO retransmissions after dropping it
        for attempt in 0..3 {
            pair.client.drive(pair.time, pair.server.addr);
            assert!(!pair.client.outbound.is_empty());
            for (transmit, data) in &pair.client.outbound {
                assert_eq!(transmit.size, usize::from(size));
                assert_eq!(data.len(), usize::from(size));
            }
            if attempt < 2 {
                pair.client.outbound.clear();
                pair.time = pair.client.next_wakeup().unwrap();
            }
        }

        let mut datagrams = Vec::new();
        for _ in 0..100 {
            pair.client.drive(pair.time, pair.server.addr);
            datagrams.extend(pair.client.outbound.iter().map(|(_, data)| data.clone()));
            if !pair.step() {
                break;
            }
        }
        // Every later datagram carrying an Initial packet has the same size
        for datagram in datagrams.iter().filter(|d| is_initial(d)) {
            assert_eq!(datagram.len(), usize::from(size));
        }
        let server_ch = pair.server.assert_accept();
        pair.finish_connect(client_ch, server_ch);
    }
}

/// Sends the second half of the CRYPTO data first, then the first half behind a PING, each
/// packet filled exactly with PADDING between frames
#[derive(Debug)]
struct SwapHalves;

impl InitialLayout for SwapHalves {
    fn plan(
        &self,
        crypto_len: u64,
        frame_space: &dyn Fn(usize) -> usize,
    ) -> Option<Vec<Vec<InitialFrame>>> {
        let half = crypto_len / 2;
        let fill = |i: usize, frames: &[InitialFrame]| {
            let used = frames.iter().map(InitialFrame::encoded_len).sum::<usize>();
            frame_space(i) - used
        };
        let tail = [
            InitialFrame::Padding(3),
            InitialFrame::Crypto {
                offset: half,
                len: crypto_len - half,
            },
            InitialFrame::Ping,
        ];
        let head = [
            InitialFrame::Ping,
            InitialFrame::Crypto {
                offset: 0,
                len: half,
            },
        ];
        let mut first = tail.to_vec();
        first.push(InitialFrame::Padding(fill(0, &tail)));
        let mut second = head.to_vec();
        second.insert(1, InitialFrame::Padding(fill(1, &head)));
        Some(vec![first, second])
    }
}

/// Covers only part of the CRYPTO data
#[derive(Debug)]
struct Invalid;

impl InitialLayout for Invalid {
    fn plan(&self, crypto_len: u64, _: &dyn Fn(usize) -> usize) -> Option<Vec<Vec<InitialFrame>>> {
        Some(vec![vec![InitialFrame::Crypto {
            offset: 0,
            len: crypto_len - 1,
        }]])
    }
}

#[test]
fn initial_layout_plan() {
    let _guard = subscribe();
    let mut transport = TransportConfig::default();
    transport
        .initial_packet_number(1)
        .packet_number_lengths(vec![1, 2])
        .initial_datagram_size(Some(1250))
        .initial_layout(Some(Arc::new(SwapHalves)));
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_config_with(transport));
    pair.client.drive(pair.time, pair.server.addr);
    let first_flight = pair
        .client
        .outbound
        .iter()
        .map(|(_, data)| data.clone())
        .collect::<Vec<_>>();
    assert_eq!(first_flight.len(), 2);
    let packets = first_flight
        .iter()
        .flat_map(|d| {
            assert_eq!(d.len(), 1250);
            client_initials(d)
        })
        .collect::<Vec<_>>();
    assert_eq!(packets.len(), 2);
    let crypto_len = match packets[1].frames[2] {
        Decoded::Crypto { offset: 0, len } => len * 2,
        ref other => panic!("unexpected {other:?}"),
    };
    let half = crypto_len / 2;
    let len = |frames: &[Decoded]| -> u64 {
        frames
            .iter()
            .filter_map(|f| match f {
                Decoded::Crypto { len, .. } => Some(*len),
                _ => None,
            })
            .sum()
    };
    let total = len(&packets[0].frames) + len(&packets[1].frames);
    assert!(matches!(
        packets[0].frames[..],
        [
            Decoded::Padding(3),
            Decoded::Crypto { offset, .. },
            Decoded::Ping,
            Decoded::Padding(_)
        ] if offset == total / 2
    ));
    assert!(matches!(
        packets[1].frames[..],
        [
            Decoded::Ping,
            Decoded::Padding(_),
            Decoded::Crypto { offset: 0, .. }
        ]
    ));
    assert!(half <= total / 2 + 1);
    assert_eq!(packets[0].number_len, 1);
    assert_eq!(packets[1].number_len, 2);

    pair.drive();
    let server_ch = pair.server.assert_accept();
    pair.finish_connect(client_ch, server_ch);
}

#[test]
fn initial_layout_retransmits_in_default_layout() {
    let _guard = subscribe();
    let mut transport = TransportConfig::default();
    transport.initial_layout(Some(Arc::new(SwapHalves)));
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_config_with(transport));
    pair.client.drive(pair.time, pair.server.addr);
    assert_eq!(pair.client.outbound.len(), 2);
    pair.client.outbound.clear();

    // The PTO retransmission carries the lost CRYPTO frames in order, without PINGs
    pair.time = pair.client.next_wakeup().unwrap();
    pair.client.drive(pair.time, pair.server.addr);
    let frames = pair
        .client
        .outbound
        .iter()
        .flat_map(|(_, d)| client_initials(d))
        .flat_map(|p| p.frames)
        .filter(|f| !matches!(f, Decoded::Padding(_)))
        .collect::<Vec<_>>();
    assert!(matches!(frames[0], Decoded::Crypto { .. }), "{frames:?}");

    pair.drive();
    let server_ch = pair.server.assert_accept();
    pair.finish_connect(client_ch, server_ch);
}

#[test]
fn invalid_initial_layout_is_ignored() {
    let _guard = subscribe();
    let mut transport = TransportConfig::default();
    transport.initial_layout(Some(Arc::new(Invalid)));
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_config_with(transport));
    pair.client.drive(pair.time, pair.server.addr);
    let packets = client_initials(&pair.client.outbound[0].1);
    assert!(matches!(
        packets[0].frames[..],
        [Decoded::Crypto { offset: 0, .. }, Decoded::Padding(_)]
    ));
    pair.drive();
    let server_ch = pair.server.assert_accept();
    pair.finish_connect(client_ch, server_ch);
}
