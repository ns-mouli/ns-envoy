#include "test/extensions/common/qosmos_dpi/pcap_reader.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>

#include <cstring>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace QosmosDpi {
namespace TestSupport {

namespace {

// Ethertypes / linktypes we recognise.
constexpr uint16_t ETH_P_IP = 0x0800;
constexpr uint16_t ETH_P_IPV6 = 0x86DD;
constexpr uint16_t ETH_P_8021Q = 0x8100;

constexpr uint8_t IPPROTO_TCP_L = 6;

// Byte cursor with a "remaining" length; every extract call bounds-checks.
struct View {
  const uint8_t* p;
  size_t len;
  bool skip(size_t n) {
    if (len < n) return false;
    p += n; len -= n; return true;
  }
  const uint8_t* take(size_t n) {
    if (len < n) return nullptr;
    const uint8_t* r = p; p += n; len -= n; return r;
  }
};

// Returns (ethertype, payload_view) after stripping link-layer + VLANs.
// On unsupported linktype returns 0.
std::pair<uint16_t, View> stripLinkLayer(int datalink, View v) {
  switch (datalink) {
    case DLT_EN10MB: {  // Ethernet II
      if (v.len < 14) return {0, v};
      uint16_t etype = (v.p[12] << 8) | v.p[13];
      v.skip(14);
      // Peel one VLAN tag if present.
      if (etype == ETH_P_8021Q && v.len >= 4) {
        etype = (v.p[2] << 8) | v.p[3];
        v.skip(4);
      }
      return {etype, v};
    }
    case DLT_RAW: {
      if (v.len < 1) return {0, v};
      uint8_t version = v.p[0] >> 4;
      if (version == 4) return {ETH_P_IP, v};
      if (version == 6) return {ETH_P_IPV6, v};
      return {0, v};
    }
    case DLT_LINUX_SLL: {   // Cooked capture v1: 16-byte header, last 2 = etype
      if (v.len < 16) return {0, v};
      uint16_t etype = (v.p[14] << 8) | v.p[15];
      v.skip(16);
      return {etype, v};
    }
    case DLT_LINUX_SLL2: {  // Cooked capture v2: 20-byte header, first 2 = etype
      if (v.len < 20) return {0, v};
      uint16_t etype = (v.p[0] << 8) | v.p[1];
      v.skip(20);
      return {etype, v};
    }
    default:
      return {0, v};
  }
}

// One packet's parsed shape.
struct Packet {
  bool is_v6{false};
  std::array<uint8_t, 16> src_ip{};
  std::array<uint8_t, 16> dst_ip{};
  uint16_t src_port_nbo{0};
  uint16_t dst_port_nbo{0};
  bool syn{false};
  bool has_payload{false};
  const uint8_t* payload{nullptr};
  size_t payload_len{0};
};

// Parse IPv4 + TCP. Returns true on success. Skips fragments other than
// offset==0.
bool parseIp4Tcp(View ip, Packet& out) {
  if (ip.len < 20) return false;
  const uint8_t ver_ihl = ip.p[0];
  if ((ver_ihl >> 4) != 4) return false;
  const size_t ihl = (ver_ihl & 0x0F) * 4;
  if (ihl < 20 || ip.len < ihl) return false;
  const uint16_t total_len = (ip.p[2] << 8) | ip.p[3];
  if (total_len < ihl || total_len > ip.len) {
    // Some captures pad or truncate; clamp to view.
  }
  const uint16_t frag_off = ((ip.p[6] & 0x1F) << 8) | ip.p[7];
  if ((frag_off & 0x1FFF) != 0) return false;  // non-zero-offset fragment
  const uint8_t proto = ip.p[9];
  if (proto != IPPROTO_TCP_L) return false;
  std::memcpy(out.src_ip.data(), &ip.p[12], 4);
  std::memcpy(out.dst_ip.data(), &ip.p[16], 4);
  out.is_v6 = false;
  const uint8_t* tcp = ip.p + ihl;
  size_t remaining = ip.len - ihl;
  // Clamp against IP total-length if reasonable.
  if (total_len > ihl && total_len - ihl < remaining) {
    remaining = total_len - ihl;
  }
  if (remaining < 20) return false;
  out.src_port_nbo = *reinterpret_cast<const uint16_t*>(tcp + 0);
  out.dst_port_nbo = *reinterpret_cast<const uint16_t*>(tcp + 2);
  const size_t doff = ((tcp[12] >> 4) & 0x0F) * 4;
  if (doff < 20 || remaining < doff) return false;
  const uint8_t flags = tcp[13];
  out.syn = (flags & 0x02) != 0;
  out.payload = tcp + doff;
  out.payload_len = remaining - doff;
  out.has_payload = out.payload_len > 0;
  return true;
}

bool parseIp6Tcp(View ip, Packet& out) {
  if (ip.len < 40) return false;
  const uint8_t ver = ip.p[0] >> 4;
  if (ver != 6) return false;
  const uint16_t payload_len = (ip.p[4] << 8) | ip.p[5];
  uint8_t next_header = ip.p[6];
  std::memcpy(out.src_ip.data(), &ip.p[8], 16);
  std::memcpy(out.dst_ip.data(), &ip.p[24], 16);
  out.is_v6 = true;
  const uint8_t* cur = ip.p + 40;
  size_t remaining = ip.len - 40;
  if (payload_len > 0 && payload_len < remaining) remaining = payload_len;
  // Walk a small fixed set of extension headers.
  for (int i = 0; i < 4 && next_header != IPPROTO_TCP_L; ++i) {
    // 0=HBH, 43=Routing, 60=DestOpts have variable-length header (rfc8200).
    if (next_header != 0 && next_header != 43 && next_header != 60 &&
        next_header != 44) {
      return false;
    }
    if (remaining < 8) return false;
    next_header = cur[0];
    const size_t hdr_len = (cur[1] + 1) * 8;
    if (remaining < hdr_len) return false;
    cur += hdr_len; remaining -= hdr_len;
  }
  if (next_header != IPPROTO_TCP_L || remaining < 20) return false;
  out.src_port_nbo = *reinterpret_cast<const uint16_t*>(cur + 0);
  out.dst_port_nbo = *reinterpret_cast<const uint16_t*>(cur + 2);
  const size_t doff = ((cur[12] >> 4) & 0x0F) * 4;
  if (doff < 20 || remaining < doff) return false;
  const uint8_t flags = cur[13];
  out.syn = (flags & 0x02) != 0;
  out.payload = cur + doff;
  out.payload_len = remaining - doff;
  out.has_payload = out.payload_len > 0;
  return true;
}

// Canonicalised 5-tuple: always order the two endpoints so both directions
// hash to the same bucket. `flipped=true` iff we swapped, i.e. this packet
// is STC relative to the first-seen direction.
struct FiveTupleKey {
  bool is_v6;
  std::array<uint8_t, 16> a_ip, b_ip;
  uint16_t a_port_nbo, b_port_nbo;
  bool operator==(const FiveTupleKey& o) const {
    return is_v6 == o.is_v6 && a_port_nbo == o.a_port_nbo &&
           b_port_nbo == o.b_port_nbo && a_ip == o.a_ip && b_ip == o.b_ip;
  }
};
struct FiveTupleHash {
  size_t operator()(const FiveTupleKey& k) const {
    size_t h = k.is_v6 ? 1 : 0;
    for (auto b : k.a_ip) h = h * 131 + b;
    for (auto b : k.b_ip) h = h * 131 + b;
    h = h * 131 + k.a_port_nbo;
    h = h * 131 + k.b_port_nbo;
    return h;
  }
};

std::pair<FiveTupleKey, bool> canonicalize(const Packet& p) {
  FiveTupleKey k{};
  k.is_v6 = p.is_v6;
  // Order endpoints by (ip, port) lexicographically so both directions hash
  // the same. Returns flipped = true iff (src,srcport) sorted AFTER
  // (dst,dstport) — i.e. src was "b".
  const size_t ip_len = p.is_v6 ? 16 : 4;
  int cmp = std::memcmp(p.src_ip.data(), p.dst_ip.data(), ip_len);
  bool src_first;
  if (cmp != 0) {
    src_first = (cmp < 0);
  } else {
    src_first = ntohs(p.src_port_nbo) < ntohs(p.dst_port_nbo);
  }
  if (src_first) {
    k.a_ip = p.src_ip; k.a_port_nbo = p.src_port_nbo;
    k.b_ip = p.dst_ip; k.b_port_nbo = p.dst_port_nbo;
    return {k, false};
  }
  k.a_ip = p.dst_ip; k.a_port_nbo = p.dst_port_nbo;
  k.b_ip = p.src_ip; k.b_port_nbo = p.src_port_nbo;
  return {k, true};
}

}  // namespace

absl::StatusOr<std::vector<TcpStream>>
PcapReader::readAllStreams(const std::string& pcap_path) {
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* pcap = pcap_open_offline(pcap_path.c_str(), errbuf);
  if (pcap == nullptr) {
    return absl::InvalidArgumentError(
        absl::StrFormat("pcap_open_offline(%s) failed: %s", pcap_path, errbuf));
  }
  const int datalink = pcap_datalink(pcap);

  // Per-stream state: canonicalized key → (stream_index, initiator_key).
  // initiator_key stores {src_ip, src_port_nbo, is_v6} for the first-seen
  // packet, so subsequent packets can figure out their direction.
  struct InitiatorKey {
    std::array<uint8_t, 16> src_ip;
    uint16_t src_port_nbo;
  };
  absl::flat_hash_map<FiveTupleKey, std::pair<uint32_t, InitiatorKey>,
                       FiveTupleHash> stream_index;
  std::vector<TcpStream> streams;

  pcap_pkthdr* hdr = nullptr;
  const u_char* data = nullptr;
  int rc;
  while ((rc = pcap_next_ex(pcap, &hdr, &data)) == 1) {
    View v{data, hdr->caplen};
    auto [etype, ipv] = stripLinkLayer(datalink, v);
    Packet pkt;
    bool ok = false;
    if (etype == ETH_P_IP) ok = parseIp4Tcp(ipv, pkt);
    else if (etype == ETH_P_IPV6) ok = parseIp6Tcp(ipv, pkt);
    if (!ok) continue;

    auto [ckey, flipped] = canonicalize(pkt);
    auto it = stream_index.find(ckey);
    if (it == stream_index.end()) {
      // First packet of a new stream. Establish direction using this
      // packet's SYN direction if present; else default to "src is CTS".
      InitiatorKey ik{pkt.src_ip, pkt.src_port_nbo};
      const uint32_t sid = static_cast<uint32_t>(streams.size());
      TcpStream stream{};
      stream.is_v6 = pkt.is_v6;
      stream.src_ip = pkt.src_ip;
      stream.dst_ip = pkt.dst_ip;
      stream.src_port_nbo = pkt.src_port_nbo;
      stream.dst_port_nbo = pkt.dst_port_nbo;
      stream.stream_id = sid;
      streams.push_back(std::move(stream));
      it = stream_index.emplace(ckey, std::make_pair(sid, ik)).first;
    }
    const uint32_t sid = it->second.first;
    const InitiatorKey& ik = it->second.second;
    Direction dir;
    if (pkt.src_ip == ik.src_ip && pkt.src_port_nbo == ik.src_port_nbo) {
      dir = Direction::CTS;
    } else {
      dir = Direction::STC;
    }
    if (pkt.has_payload) {
      Chunk c;
      c.direction = dir;
      c.bytes.assign(pkt.payload, pkt.payload + pkt.payload_len);
      streams[sid].chunks.push_back(std::move(c));
    }
    (void)flipped;
  }
  pcap_close(pcap);

  // Drop streams with no payload — they carry no signal.
  std::vector<TcpStream> nonempty;
  nonempty.reserve(streams.size());
  uint32_t new_id = 0;
  for (auto& s : streams) {
    if (s.chunks.empty()) continue;
    s.stream_id = new_id++;
    nonempty.push_back(std::move(s));
  }
  return nonempty;
}

}  // namespace TestSupport
}  // namespace QosmosDpi
}  // namespace Common
}  // namespace Extensions
}  // namespace Envoy
