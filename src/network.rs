//! Reaches the Moodle someone named. Anyone can enter any address, so an address
//! must never reach this server's own network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Url, redirect};

use crate::config::user_agent;
use crate::error::{MoodleError, Result};
use crate::moodle::{Login, MoodleClient};

const ADDRESS_RULES: &str = "The address must be a public https address.";
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addresses {
    PublicOnly,
    /// For tests, whose stand-in Moodle runs on this computer.
    Any,
}

pub struct Network {
    http: reqwest::Client,
    addresses: Addresses,
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..20).contains(&b)))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    let [first, second, ..] = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || (first == 0x2001 && second == 0x0db8)
        || first == 0x0064)
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

/// Checking when connecting, not only when reading the address, also catches a
/// name that resolves to something else the second time.
struct PublicAddresses;

impl Resolve for PublicAddresses {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let public: Vec<SocketAddr> = found.filter(|address| is_public(address.ip())).collect();
            if public.is_empty() {
                return Err("the name has no public address".into());
            }
            let addresses: Addrs = Box::new(public.into_iter());
            Ok(addresses)
        })
    }
}

fn allowed_url(url: &Url) -> bool {
    let public_host = match url.host() {
        Some(url::Host::Domain(_)) => true,
        Some(url::Host::Ipv4(ip)) => is_public_v4(ip),
        Some(url::Host::Ipv6(ip)) => is_public_v6(ip),
        None => false,
    };
    url.scheme() == "https"
        && public_host
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(url.port(), None | Some(443))
}

fn client(addresses: Addresses) -> reqwest::Client {
    let builder = reqwest::Client::builder()
        .user_agent(user_agent())
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(5))
        .no_proxy();
    let builder = match addresses {
        Addresses::Any => builder,
        Addresses::PublicOnly => {
            builder
                .dns_resolver(Arc::new(PublicAddresses))
                .redirect(redirect::Policy::custom(|attempt| {
                    if attempt.previous().len() >= MAX_REDIRECTS || !allowed_url(attempt.url()) {
                        attempt.stop()
                    } else {
                        attempt.follow()
                    }
                }))
        }
    };
    builder
        .build()
        .expect("the HTTP client has a valid configuration")
}

impl Network {
    pub fn new(addresses: Addresses) -> Self {
        Self {
            http: client(addresses),
            addresses,
        }
    }

    /// The address of a Moodle, which may sit in a subfolder, ending in a slash.
    pub fn moodle_address(&self, address: &str) -> Result<Url> {
        let address = address.trim();
        if address.is_empty() {
            return Err(MoodleError::new("Enter the Moodle address."));
        }
        let address = if address.contains("://") {
            address.to_owned()
        } else {
            format!("https://{address}")
        };
        let mut url = Url::parse(&address).map_err(|_| MoodleError::new(ADDRESS_RULES))?;
        if self.addresses == Addresses::PublicOnly && !allowed_url(&url) {
            return Err(MoodleError::new(ADDRESS_RULES));
        }
        url.path_segments_mut()
            .map_err(|()| MoodleError::new(ADDRESS_RULES))?
            .pop_if_empty()
            .push("");
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }

    pub fn client(&self, login: &Login) -> Result<MoodleClient> {
        Ok(MoodleClient::new(
            self.http.clone(),
            self.moodle_address(&login.moodle)?,
            login.token.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> Result<String> {
        Network::new(Addresses::PublicOnly)
            .moodle_address(text)
            .map(|url| url.to_string())
    }

    #[test]
    fn a_host_name_is_enough_and_a_subfolder_is_kept() {
        assert_eq!(
            address(" moodle.example.org ").expect("an address"),
            "https://moodle.example.org/"
        );
        assert_eq!(
            address("https://uni.example.org/moodle").expect("an address"),
            "https://uni.example.org/moodle/"
        );
    }

    #[test]
    fn only_public_https_addresses_are_taken() {
        for refused in [
            "",
            "http://moodle.example.org",
            "ftp://moodle.example.org",
            "https://user:secret@moodle.example.org",
            "https://moodle.example.org:8080",
            "127.0.0.1",
            "https://10.0.0.5",
            "https://169.254.169.254/metadata",
            "https://[::1]",
            "https://[::ffff:10.0.0.5]",
            "https://[fd00::1]",
            "not an address",
        ] {
            assert!(address(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn internal_addresses_are_not_public() {
        for text in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "::ffff:192.168.1.1",
            "64:ff9b::a00:1",
        ] {
            let ip: IpAddr = text.parse().expect("an address");
            assert!(!is_public(ip), "{text}");
        }
        for text in ["134.130.1.1", "8.8.8.8", "2a00:1450:4001::1"] {
            let ip: IpAddr = text.parse().expect("an address");
            assert!(is_public(ip), "{text}");
        }
    }

    #[tokio::test]
    async fn a_name_for_this_computer_is_refused_when_connecting() {
        let name: Name = "localhost".parse().expect("a name");
        assert!(PublicAddresses.resolve(name).await.is_err());
    }
}
