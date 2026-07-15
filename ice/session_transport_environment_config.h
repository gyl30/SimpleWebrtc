#ifndef SIMPLE_WEBRTC_ICE_SESSION_TRANSPORT_ENVIRONMENT_CONFIG_H
#define SIMPLE_WEBRTC_ICE_SESSION_TRANSPORT_ENVIRONMENT_CONFIG_H

#include <string>

#include "dtls/dtls_transport.h"
#include "net/udp_port_allocator.h"

namespace webrtc
{
struct session_transport_runtime_config
{
    dtls_transport_config dtls_transport;

    udp_port_range session_udp_port_range;

    std::string validation_error;
};

const session_transport_runtime_config& session_transport_runtime_config_instance();
}    // namespace webrtc

#endif
