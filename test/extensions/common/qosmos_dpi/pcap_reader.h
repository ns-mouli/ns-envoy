#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace QosmosDpi {
namespace TestSupport {

// Direction relative to the stream's initiator (the TCP SYN sender).
enum class Direction : uint8_t { CTS = 0, STC = 1 };

// One payload chunk in packet order.
struct Chunk {
  Direction direction;
  std::vector<uint8_t> bytes;    // TCP payload only (L7).
};

// One TCP stream extracted from a pcap: 5-tuple + ordered payload chunks.
struct TcpStream {
  bool is_v6{false};
  std::array<uint8_t, 16> src_ip{};   // v4 uses the first 4 bytes.
  std::array<uint8_t, 16> dst_ip{};
  uint16_t src_port_nbo{0};            // network-byte-order
  uint16_t dst_port_nbo{0};
  std::vector<Chunk> chunks;           // ordered by capture time
  uint32_t stream_id{0};               // 0-based index in this pcap
};

// Minimal libpcap-based reader. Not a full packet library — just enough to
// feed the Qosmos engine.
//
// - Handles Ethernet + linktype LINUX_SLL / SLL2 / RAW_IPv4/IPv6.
// - Detects VLAN 802.1Q one deep.
// - IPv4 fragmentation is not reassembled (rare in this corpus; those
//   packets are skipped).
// - TCP options are skipped; only doff is honoured.
// - Streams are identified by their SYN packet's 5-tuple. Packets seen
//   before any SYN (mid-stream captures) are attached to a stream keyed
//   on the ordered {src,dst,srcport,dstport} tuple, with the first-seen
//   direction taken as CTS.
class PcapReader {
public:
  // Read all TCP streams from `pcap_path` in-order. On success returns a
  // vector where each entry is one stream in the pcap; on failure returns
  // a status. Streams with zero payload chunks are omitted.
  static absl::StatusOr<std::vector<TcpStream>>
  readAllStreams(const std::string& pcap_path);
};

}  // namespace TestSupport
}  // namespace QosmosDpi
}  // namespace Common
}  // namespace Extensions
}  // namespace Envoy
