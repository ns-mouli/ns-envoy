# Trimmed extensions_build_config.bzl for the qosmos_dpi phase-1 work.
# Only extensions that topology-C actually references (plus tls_inspector,
# which the verdict-cache plan will add) are kept enabled. All others are
# commented out. This exists to shrink the envoy-static link's peak RSS
# below the 8 GB swap threshold and cut clean-build time from ~12 h to ~1-2 h.
#
# Selected via --override_repository=envoy_build_config=%workspace%/netskope/build_config
# in netskope.bazelrc (config=ns-clang-trim). Upstream default lives at
# source/extensions/extensions_build_config.bzl and is not affected.
#
# When adding envoy.filters.network.qosmos_dpi_correction (per the verdict-
# cache plan), add the entry here too.

EXTENSIONS = {
    #
    # Access loggers -- topology-C uses file logger to /dev/stdout
    #
    "envoy.access_loggers.file":                        "//source/extensions/access_loggers/file:config",
    "envoy.access_loggers.stdout":                      "//source/extensions/access_loggers/stream:config",
    "envoy.access_loggers.stderr":                      "//source/extensions/access_loggers/stream:config",

    #
    # Clusters -- topology-C uses ORIGINAL_DST clusters only
    #
    "envoy.clusters.original_dst":                      "//source/extensions/clusters/original_dst:original_dst_cluster_lib",
    # static/strict_dns/logical_dns kept as core; some are pulled in
    # by cluster_manager machinery even when no listener uses them.
    "envoy.clusters.static":                            "//source/extensions/clusters/static:static_cluster_lib",
    "envoy.clusters.strict_dns":                        "//source/extensions/clusters/strict_dns:strict_dns_cluster_lib",
    "envoy.clusters.logical_dns":                       "//source/extensions/clusters/logical_dns:logical_dns_cluster_lib",

    #
    # Config validators (leave the built-in min-clusters validator on; harmless)
    #
    "envoy.config.validators.minimum_clusters_validator":     "//source/extensions/config/validators/minimum_clusters:config",

    #
    # Network Matchers -- required by listener match machinery even for
    # static configs; small footprint.
    #
    "envoy.matching.inputs.application_protocol":       "//source/extensions/matching/network/application_protocol:config",
    "envoy.matching.inputs.destination_ip":             "//source/extensions/matching/network/common:inputs_lib",
    "envoy.matching.inputs.destination_port":           "//source/extensions/matching/network/common:inputs_lib",
    "envoy.matching.inputs.source_ip":                  "//source/extensions/matching/network/common:inputs_lib",
    "envoy.matching.inputs.source_port":                "//source/extensions/matching/network/common:inputs_lib",
    "envoy.matching.inputs.direct_source_ip":           "//source/extensions/matching/network/common:inputs_lib",
    "envoy.matching.inputs.source_type":                "//source/extensions/matching/network/common:inputs_lib",
    "envoy.matching.inputs.server_name":                "//source/extensions/matching/network/common:inputs_lib",
    "envoy.matching.inputs.network_namespace":          "//source/extensions/matching/network/common:inputs_lib",
    "envoy.matching.inputs.transport_protocol":         "//source/extensions/matching/network/common:inputs_lib",
    "envoy.matching.inputs.filter_state":               "//source/extensions/matching/network/common:inputs_lib",

    #
    # Listener filters -- ONLY the four we actually need
    #
    "envoy.filters.listener.original_dst":              "//source/extensions/filters/listener/original_dst:config",
    "envoy.filters.listener.tls_inspector":             "//source/extensions/filters/listener/tls_inspector:config",
    "envoy.filters.listener.qosmos_dpi":                "//source/extensions/filters/listener/qosmos_dpi:config",

    #
    # Network filters -- tcp_proxy + qosmos_dpi_correction (Part E of the
    # verdict-cache plan)
    #
    "envoy.filters.network.qosmos_dpi_correction":                "//source/extensions/filters/network/qosmos_dpi_correction:config",
    "envoy.filters.network.tcp_proxy":                            "//source/extensions/filters/network/tcp_proxy:config",

    #
    # Resource monitors (fixed_heap is standard, keep it)
    #
    "envoy.resource_monitors.fixed_heap":               "//source/extensions/resource_monitors/fixed_heap:config",
    "envoy.resource_monitors.global_downstream_max_connections":   "//source/extensions/resource_monitors/downstream_connections:config",

    #
    # Transport sockets -- raw_buffer for TCP; tls only for tls_inspector
    #
    "envoy.transport_sockets.raw_buffer":               "//source/extensions/transport_sockets/raw_buffer:config",
    "envoy.transport_sockets.tls":                      "//source/extensions/transport_sockets/tls:config",

    #
    # Http Upstreams -- only tcp; needed for tcp_proxy upstream binding
    #
    "envoy.upstreams.http.tcp":                         "//source/extensions/upstreams/http/tcp:config",

    #
    # Retry priorities (default set kept, tiny)
    #
    "envoy.retry_priorities.previous_priorities":       "//source/extensions/retry/priority/previous_priorities:config",

    #
    # Load balancing policies -- topology-C uses CLUSTER_PROVIDED only
    #
    "envoy.load_balancing_policies.cluster_provided":  "//source/extensions/load_balancing_policies/cluster_provided:config",
    "envoy.load_balancing_policies.round_robin":       "//source/extensions/load_balancing_policies/round_robin:config",

    #
    # Config subscription -- static bootstrap only; drop gRPC/xDS/REST
    #
    "envoy.config_subscription.filesystem": "//source/extensions/config_subscription/filesystem:filesystem_subscription_lib",

    #
    # DNS Resolver -- c-ares kept as core (cluster init warms up even for ORIGINAL_DST)
    #
    "envoy.network.dns_resolver.cares":                "//source/extensions/network/dns_resolver/cares:config",

    #
    # Header validators -- default HTTP header validator kept (harmless)
    #
    "envoy.http.header_validators.envoy_default":        "//source/extensions/http/header_validators/envoy_default:config",

    #
    # Early data policy default (referenced by generic route machinery)
    #
    "envoy.route.early_data_policy.default":           "//source/extensions/early_data:default_early_data_policy_lib",

    #
    # Key value store (harmless; small)
    #
    "envoy.key_value.file_based":     "//source/extensions/key_value/file_based:config_lib",

    # -----------------------------------------------------------------
    # Everything below this line is commented out relative to the
    # upstream extensions_build_config.bzl. Includes:
    #   - all HTTP filters (~65)             -- topology has no HCM
    #   - all tracers + OTel resource detectors + samplers
    #   - all WASM runtimes + wasm bootstrap/access loggers/stat sinks
    #   - all thrift/dubbo/mongo/redis/kafka/postgres/zookeeper/mysql/mcp
    #   - all QUIC extensions                -- TCP only
    #   - all UDP filters / session filters
    #   - all stat sinks (statsd/dogstatsd/hystrix/OTel/graphite)
    #   - all compression codecs
    #   - all cache/cache_v2 backends
    #   - all matcher inputs beyond core network 5-tuple
    #   - all cert validators/selectors/mappers (mTLS not used)
    #   - all injected credentials, oauth, jwt, rbac, ext_authz, ext_proc
    #   - all dynamic modules, dynamic_forward_proxy, sni_cluster
    #   - all reverse_tunnel, generic_proxy, echo, direct_response
    #   - all http upstreams except tcp
    #   - all string matchers (lua), lua filters
    #   - all formatters beyond built-in
    #   - all geoip / maxmind
    #   - all bootstrap.internal_listener, io_socket.user_space
    #   - all path pattern match/rewrite, cluster specifier plugins
    #   - all content parsers (json), rate limit descriptors
    #   - all health checkers (topology uses no active hc)
    #   - all internal_redirect_predicates, retry host predicates
    #   - all http.stateful_session, header_mutation, custom_response
    #   - all local_address_selectors
    # -----------------------------------------------------------------
}

EXTENSION_CONFIG_VISIBILITY = ["//:extension_config", "//:contrib_library", "//:mobile_library"]
EXTENSION_PACKAGE_VISIBILITY = ["//:extension_library", "//:contrib_library", "//:mobile_library"]
CONTRIB_EXTENSION_PACKAGE_VISIBILITY = ["//:contrib_library"]
MOBILE_PACKAGE_VISIBILITY = ["//:mobile_library"]

LEGACY_ALWAYSLINK = 1
