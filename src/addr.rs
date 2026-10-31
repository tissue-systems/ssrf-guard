use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::Error;

/// Whether `ip` is an address a fetch may reach under the built-in rules.
///
/// False for loopback, private, link-local, carrier-grade NAT, multicast,
/// broadcast, documentation, benchmarking and reserved space. In IPv6 that's
/// loopback, unique local, link-local, the deprecated site-local block,
/// multicast, documentation, benchmarking, the discard prefix and SRv6
/// segment IDs. An IPv6 address with an IPv4 address inside it (mapped,
/// compatible, SIIT or NAT64) is judged by the IPv4 address. 6to4, Teredo
/// and local-use NAT64 are refused whatever they carry.
///
/// ```
/// use ssrf_guard::is_public;
///
/// assert!(is_public("93.184.215.14".parse().unwrap()));
/// assert!(!is_public("169.254.169.254".parse().unwrap()));
/// assert!(!is_public("::ffff:10.1.2.3".parse().unwrap()));
/// ```
pub fn is_public(ip: IpAddr) -> bool {
    !denied(ip)
}

pub(crate) fn denied(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_denied(v4),
        IpAddr::V6(v6) => v6_denied(v6),
    }
}

fn v4_denied(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // 10/8, 172.16/12, 192.168/16, RFC 1918
    ip.is_private()
        // 127/8, RFC 1122
        || ip.is_loopback()
        // 169.254/16, RFC 3927, where cloud metadata services answer
        || ip.is_link_local()
        || ip.is_unspecified()
        // 255.255.255.255, RFC 919
        || ip.is_broadcast()
        // 224/4, RFC 5771
        || ip.is_multicast()
        // 192.0.2/24, 198.51.100/24, 203.0.113/24, RFC 5737
        || ip.is_documentation()
        // 0/8, RFC 1122. Linux connects 0.0.0.0 to the local host.
        || o[0] == 0
        // 100.64/10, RFC 6598, carrier-grade NAT, which some VPNs and
        // overlay networks use too
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        // 192.0.0/24, RFC 6890, IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 192.88.99/24, RFC 7526, the deprecated 6to4 relay anycast block.
        // Refused for the same reason 6to4 is, below.
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        // 198.18/15, RFC 2544, benchmarking
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        // 240/4, RFC 1112, reserved
        || o[0] >= 240
}

fn v6_denied(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return v4_denied(v4);
    }
    let seg = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        // ff00::/8, RFC 4291
        || ip.is_multicast()
        // 2002::/16 (6to4, RFC 3056) and 2001::/32 (Teredo, RFC 4380).
        // Where these packets come out is up to a relay you don't control,
        // so the address inside them doesn't say where the connection lands.
        || seg[0] == 0x2002
        || (seg[0] == 0x2001 && seg[1] == 0)
        // 64:ff9b:1::/48, RFC 8215, local-use NAT64, refused whole for the
        // same reason
        || seg[..3] == [0x64, 0xff9b, 1]
        // fe80::/10, RFC 4291, link-local
        || (seg[0] & 0xffc0) == 0xfe80
        // fec0::/10, RFC 3879, site-local. Deprecated, but some stacks still
        // route it locally.
        || (seg[0] & 0xffc0) == 0xfec0
        // fc00::/7, RFC 4193, unique local
        || (seg[0] & 0xfe00) == 0xfc00
        // 2001:db8::/32 (RFC 3849) and 3fff::/20 (RFC 9637), documentation
        || (seg[0] == 0x2001 && seg[1] == 0x0db8)
        || (seg[0] == 0x3fff && seg[1] < 0x1000)
        // 2001:2::/48, RFC 5180, benchmarking
        || seg[..3] == [0x2001, 2, 0]
        // 100::/64, RFC 6666, discard-only
        || seg[..4] == [0x100, 0, 0, 0]
        // 5f00::/16, RFC 9602, SRv6 segment IDs, not globally reachable
        || seg[0] == 0x5f00
}

/// The IPv4 address carried inside an IPv6 one: `::ffff:a.b.c.d` (mapped),
/// `64:ff9b::a.b.c.d` (NAT64), and two deprecated forms, `::a.b.c.d`
/// (compatible, but not `::` or `::1`) and `::ffff:0:a.b.c.d` (SIIT,
/// RFC 2765). Few stacks still route those two, but the IPv4 inside them is
/// what gets checked.
pub(crate) fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let seg = ip.segments();
    let compatible = seg[..6] == [0; 6] && !ip.is_loopback() && !ip.is_unspecified();
    let siit = seg[..6] == [0, 0, 0, 0, 0xffff, 0];
    if compatible || siit || seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [.., a, b, c, d] = ip.octets();
        return Some(Ipv4Addr::new(a, b, c, d));
    }
    None
}

/// An address block, such as `203.0.113.0/24` or `2001:db8::/32`. A bare
/// address parses as a block of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// The block of `prefix` leading bits of `addr`. Host bits are cleared,
    /// so `10.1.2.3/8` is `10.0.0.0/8`.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Cidr, Error> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(Error::InvalidCidr(format!("{addr}/{prefix}")));
        }
        let addr = match addr {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask32(prefix))),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask128(prefix))),
        };
        Ok(Cidr { addr, prefix })
    }

    /// The first address of the block.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is in the block. An IPv4 block also holds the IPv6
    /// spellings of its addresses (see [`is_public`]), and an IPv6 block
    /// holds those spellings as written, so `::ffff:0:0/96` holds every
    /// mapped address.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => self.holds_v4(net, ip),
            (IpAddr::V4(net), IpAddr::V6(ip)) => {
                embedded_v4(ip).is_some_and(|ip| self.holds_v4(net, ip))
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(ip) & mask128(self.prefix) == u128::from(net)
            }
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }

    fn holds_v4(&self, net: Ipv4Addr, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask32(self.prefix) == u32::from(net)
    }
}

fn mask32(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask128(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

impl From<IpAddr> for Cidr {
    fn from(addr: IpAddr) -> Cidr {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Cidr { addr, prefix }
    }
}

impl FromStr for Cidr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Cidr, Error> {
        let bad = || Error::InvalidCidr(s.to_string());
        match s.split_once('/') {
            None => s.parse::<IpAddr>().map(Cidr::from).map_err(|_| bad()),
            Some((addr, prefix)) => {
                let addr = addr.parse::<IpAddr>().map_err(|_| bad())?;
                // u8::from_str takes a leading '+', which a prefix shouldn't have.
                if !prefix.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(bad());
                }
                let prefix = prefix.parse::<u8>().map_err(|_| bad())?;
                Cidr::new(addr, prefix).map_err(|_| bad())
            }
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_table() {
        for bad in [
            "10.1.2.3",
            "10.255.255.254",
            "172.16.5.4",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.254",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.0.8",
            "192.88.99.1",
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.9",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "fc12::3",
            "ff02::1",
            "fec0::1",
            "feff::1",
            "3fff::1",
            "3fff:fff::1",
            "2001:2::1",
            "2001:2:0:ffff::1",
            "100::1",
            "::ffff:10.1.2.3",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::a01:203",
            "2001:db8::1",
            // 6to4 with a public and a private address inside, Teredo, and
            // local-use NAT64, all refused whatever they carry.
            "2002:808:808::1",
            "2002:a01:203::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001::1",
            "64:ff9b:1::808:808",
            "64:ff9b:1:ffff::1",
            // SIIT, judged by the IPv4 address inside.
            "::ffff:0:a00:4",
            "::ffff:0:7f00:1",
            "5f00::1",
            "5f00:ffff::1",
        ] {
            assert!(!is_public(bad.parse().unwrap()), "{bad} should be denied");
        }
        for good in [
            "1.1.1.1",
            "8.8.8.8",
            "100.128.0.1",
            "100.63.255.255",
            "172.32.0.1",
            "198.20.0.1",
            "192.0.1.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "::8.8.8.8",
            "64:ff9b::808:808",
            "2001:4860:4860::8888",
            "2003::1",
            "192.88.98.1",
            "192.88.100.1",
            "3ffe::1",
            "3fff:1000::1",
            "4000::1",
            "2001:2:1::1",
            "2001:3::1",
            "100:0:0:1::1",
            "fe7f::1",
            "::ffff:0:808:808",
            "5eff::1",
            "5f01::1",
            "2001:20::1",
            "2001:30::1",
        ] {
            assert!(is_public(good.parse().unwrap()), "{good} should be allowed");
        }
    }

    #[test]
    fn cidr_parsing() {
        let net: Cidr = "10.1.2.3/8".parse().unwrap();
        assert_eq!(net.to_string(), "10.0.0.0/8");
        assert_eq!(net.addr().to_string(), "10.0.0.0");
        assert_eq!(net.prefix(), 8);
        assert_eq!(
            "2001:db8::1".parse::<Cidr>().unwrap().to_string(),
            "2001:db8::1/128"
        );
        assert_eq!(
            "0.0.0.0/0".parse::<Cidr>().unwrap().to_string(),
            "0.0.0.0/0"
        );
        for bad in [
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "example.com",
            "10.0.0/8",
            "",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn cidr_membership() {
        let net: Cidr = "203.0.113.0/24".parse().unwrap();
        assert!(net.contains("203.0.113.200".parse().unwrap()));
        assert!(!net.contains("203.0.114.1".parse().unwrap()));
        // The IPv6 spellings of an address in the block are in it too.
        assert!(net.contains("::ffff:203.0.113.5".parse().unwrap()));
        assert!(net.contains("64:ff9b::cb00:7105".parse().unwrap()));
        assert!(!net.contains("2001:db8::1".parse().unwrap()));

        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        let v6: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert!(!v6.contains("10.1.2.3".parse().unwrap()));

        // An IPv6 block matches the IPv6 spellings of IPv4 addresses too.
        let ip = |s: &str| s.parse().unwrap();
        let nat64: Cidr = "64:ff9b::/96".parse().unwrap();
        assert!(nat64.contains(ip("64:ff9b::808:808")));
        assert!(!nat64.contains(ip("8.8.8.8")));
        let mapped: Cidr = "::ffff:0:0/96".parse().unwrap();
        assert!(mapped.contains(ip("::ffff:8.8.8.8")));
        let no_v6: Cidr = "::/0".parse().unwrap();
        assert!(no_v6.contains(ip("::ffff:8.8.8.8")));
        assert!(no_v6.contains(ip("::8.8.8.8")));
        assert!(!no_v6.contains(ip("8.8.8.8")));
    }
}
