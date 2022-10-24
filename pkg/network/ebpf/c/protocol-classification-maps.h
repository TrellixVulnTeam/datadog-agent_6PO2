#ifndef __PROTOCOL_CLASSIFICATION_MAPS_H
#define __PROTOCOL_CLASSIFICATION_MAPS_H

#include "protocol-classification-defs.h"
#include "map-defs.h"

// Maps a connection tuple to its classified protocol. Used to reduce redundant classification procedures on the same
// connection. Assumption: each connection has a single protocol.
BPF_HASH_MAP(connection_protocol, conn_tuple_t, protocol_t, 1024)

// Maps skb connection tuple to socket connection tuple.
// On ingress, skb connection tuple is pre NAT, and socket connection tuple is post NAT, and on egress, the opposite.
// We track the lifecycle of socket using tracepoint net/net_dev_queue.
BPF_HASH_MAP(skb_conn_tuple_to_socket_conn_tuple, conn_tuple_t, conn_tuple_t, 1024)

// Maps a connection tuple to latest tcp segment we've processed. Helps to detect same packets that travels multiple
// interfaces or retransmissions.
BPF_HASH_MAP(connection_states, conn_tuple_t, u32, 1024)

/* Map used to store the sub program actually used by the socket filter.
 * This is done to avoid memory limitation when attaching a filter to
 * a socket.
 * See: https://datadoghq.atlassian.net/wiki/spaces/NET/pages/2326855913/HTTP#Program-size-limit-for-socket-filters */
BPF_PROG_ARRAY(protocols_progs, MAX_PROTOCOLS)

#endif
