use std::net::IpAddr;
use std::str::FromStr;

use aros_types::{AllowedEndpoint, NetworkIntent, ProtocolKind};

pub fn host_is_public_unspecified_or_broadcast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_unspecified() || v.is_broadcast() || v.is_multicast(),
        IpAddr::V6(v) => v.is_unspecified() || v.is_multicast(),
    }
}

pub fn parse_host_ip(host: &str) -> Option<IpAddr> {
    let trimmed = host.trim().trim_matches(['[', ']']);
    IpAddr::from_str(trimmed).ok()
}

pub fn network_allowed(intent: &NetworkIntent, endpoints: &[AllowedEndpoint]) -> bool {
    let Some(ip) = parse_host_ip(&intent.host) else {
        // Hostnames are not implicitly allowed; service-name allow is a
        // separate check in the engine.
        return false;
    };
    if host_is_public_unspecified_or_broadcast(ip) {
        return false;
    }
    endpoints.iter().any(|ep| {
        ep.cidr.contains(&ip)
            && ep.ports.contains(&intent.port)
            && ep.protocols.contains(&intent.protocol)
    })
}

pub fn default_denied_examples() -> Vec<NetworkIntent> {
    vec![
        NetworkIntent {
            host: "8.8.8.8".into(),
            port: 53,
            protocol: ProtocolKind::Udp,
        },
        NetworkIntent {
            host: "1.1.1.1".into(),
            port: 443,
            protocol: ProtocolKind::Https,
        },
        NetworkIntent {
            host: "2001:4860:4860::8888".into(),
            port: 53,
            protocol: ProtocolKind::Udp,
        },
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use std::str::FromStr;

    fn loopback_http() -> AllowedEndpoint {
        AllowedEndpoint {
            cidr: IpNet::from_str("127.0.0.1/32").expect("cidr"),
            ports: BTreeSet::from([8080]),
            protocols: BTreeSet::from([ProtocolKind::Http, ProtocolKind::Tcp]),
        }
    }

    #[test]
    fn public_dns_denied() {
        let allow = [loopback_http()];
        for intent in default_denied_examples() {
            assert!(!network_allowed(&intent, &allow), "{intent:?}");
        }
    }

    #[test]
    fn loopback_allowed_only_on_listed_port() {
        let allow = [loopback_http()];
        let ok = NetworkIntent {
            host: "127.0.0.1".into(),
            port: 8080,
            protocol: ProtocolKind::Http,
        };
        let bad_port = NetworkIntent {
            host: "127.0.0.1".into(),
            port: 22,
            protocol: ProtocolKind::Http,
        };
        assert!(network_allowed(&ok, &allow));
        assert!(!network_allowed(&bad_port, &allow));
    }

    #[test]
    fn ipv6_does_not_inherit_ipv4_allow() {
        let allow = [loopback_http()];
        let v6 = NetworkIntent {
            host: "::1".into(),
            port: 8080,
            protocol: ProtocolKind::Http,
        };
        assert!(!network_allowed(&v6, &allow));
    }

    proptest! {
        #[test]
        fn arbitrary_unlisted_loopback_port_is_denied(port in any::<u16>().prop_filter(
            "exclude the sole authorized port",
            |port| *port != 8080,
        )) {
            let intent = NetworkIntent {
                host: "127.0.0.1".into(),
                port,
                protocol: ProtocolKind::Http,
            };
            prop_assert!(!network_allowed(&intent, &[loopback_http()]));
        }

        #[test]
        fn arbitrary_ipv4_address_cannot_inherit_exact_loopback_allow(
            a in any::<u8>(),
            b in any::<u8>(),
            c in any::<u8>(),
            d in any::<u8>(),
        ) {
            let host = format!("{a}.{b}.{c}.{d}");
            let intent = NetworkIntent {
                host: host.clone(),
                port: 8080,
                protocol: ProtocolKind::Http,
            };
            let allowed = host == "127.0.0.1";
            prop_assert_eq!(network_allowed(&intent, &[loopback_http()]), allowed);
        }

        #[test]
        fn arbitrary_hostname_is_not_implicitly_authorized(
            label in "[a-zA-Z0-9-]{1,24}"
        ) {
            let intent = NetworkIntent {
                host: format!("{label}.invalid"),
                port: 8080,
                protocol: ProtocolKind::Http,
            };
            prop_assert!(!network_allowed(&intent, &[loopback_http()]));
        }
    }
}
