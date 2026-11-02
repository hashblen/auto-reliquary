use super::*;

const VERSION: u32 = 0x11223344;

fn key() -> Vec<u8> {
    let mut key = VERSION.to_be_bytes().to_vec();
    key.extend_from_slice(&[0x55; 28]);
    key
}

fn sniffer() -> GameSniffer {
    GameSniffer::new().set_initial_keys(HashMap::from([(VERSION, key())]))
}

/// A command with no body, encrypted with `key`.
fn command(key: &[u8]) -> Vec<u8> {
    let mut data = HEAD_MAGIC.to_be_bytes().to_vec();
    data.extend_from_slice(&[0; 8]);
    data.extend_from_slice(&[0xAA; 4]);
    decrypt_command(key, &mut data);
    data
}

/// An Ethernet frame holding a UDP packet to the game's first port.
fn udp_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    etherparse::PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4([1, 1, 1, 1], [2, 2, 2, 2], 64)
        .udp(5000, PORTS[0])
        .write(&mut frame, payload)
        .unwrap();
    frame
}

#[test]
fn malformed_packets_are_ignored() {
    let mut sniffer = GameSniffer::new();
    // Too short for a control code, for a KCP header, and with a KCP segment
    // that claims more content than there is.
    let mut lying = vec![0; 28];
    lying[24..28].copy_from_slice(&1000u32.to_le_bytes());
    for payload in [&[1u8, 2][..], &[0; 26][..], &lying[..]] {
        assert!(sniffer.receive_packet(udp_frame(payload)).is_ok());
    }
}

#[test]
fn an_unknown_key_fails_after_a_few_packets_instead_of_panicking() {
    let mut sniffer = sniffer();
    let unknown = vec![0x77; 32];
    for _ in 1..MAX_KEY_FAILURES {
        assert!(sniffer.receive_command(command(&unknown)).unwrap().is_none());
    }
    assert_eq!(
        sniffer.receive_command(command(&unknown)).err(),
        Some(SniffError::InitialKeyMissing {
            version: Some(0x77777777),
            saw_handshake: false,
        })
    );
}

#[test]
fn a_dispatch_key_that_stops_working_means_no_seed_was_seen() {
    let mut sniffer = sniffer();
    sniffer.receive_command(command(&key())).unwrap();
    let other = vec![0x77; 32];
    for _ in 1..MAX_KEY_FAILURES {
        assert!(sniffer.receive_command(command(&other)).unwrap().is_none());
    }
    assert_eq!(
        sniffer.receive_command(command(&other)).err(),
        Some(SniffError::SessionSeedMissing)
    );
}

#[test]
fn a_session_key_that_stops_working_is_lost_only_when_it_keeps_failing() {
    let mut sniffer = sniffer();
    sniffer.key = Some(Key::Session(key()));
    let other = vec![0x77; 32];

    // Packets in flight across the key change are not a problem.
    for _ in 1..MAX_KEY_FAILURES {
        assert!(sniffer.receive_command(command(&other)).unwrap().is_none());
    }
    assert!(sniffer.receive_command(command(&key())).unwrap().is_some());

    for _ in 1..MAX_KEY_FAILURES {
        assert!(sniffer.receive_command(command(&other)).unwrap().is_none());
    }
    assert_eq!(
        sniffer.receive_command(command(&other)).err(),
        Some(SniffError::SessionKeyLost)
    );
}

#[test]
fn a_reset_keeps_the_initial_keys() {
    let mut sniffer = sniffer();
    sniffer.receive_command(command(&key())).unwrap();
    sniffer.reset();
    assert_eq!(sniffer.key_state(), KeyState::None);
    assert!(sniffer.receive_command(command(&key())).unwrap().is_some());
}
