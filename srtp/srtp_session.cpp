#include "srtp/srtp_session.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <srtp2/srtp.h>

#include "dtls/dtls_srtp_keying_material.h"

namespace webrtc
{
namespace
{
inline constexpr std::size_t k_srtp_master_key_and_salt_size = k_srtp_aes128_master_key_size + k_srtp_aes128_master_salt_size;

using srtp_master_key_and_salt = std::array<uint8_t, k_srtp_master_key_and_salt_size>;

std::string srtp_error_to_string(srtp_err_status_t status);

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

srtp_err_status_t init_srtp_once()
{
    static std::once_flag once;
    static srtp_err_status_t status = srtp_err_status_ok;

    std::call_once(once, []() { status = srtp_init(); });

    return status;
}

std::expected<void, std::string> validate_profile(srtp_profile_id profile)
{
    if (profile == srtp_profile_id::unknown)
    {
        return make_error("srtp profile is unknown");
    }

    return {};
}

srtp_ssrc_type_t make_ssrc_type(srtp_direction direction)
{
    switch (direction)
    {
        case srtp_direction::inbound:
            return ssrc_any_inbound;

        case srtp_direction::outbound:
            return ssrc_any_outbound;
    }

    return ssrc_any_inbound;
}

std::expected<void, std::string> set_crypto_policy(srtp_profile_id profile, srtp_policy_t& policy)
{
    switch (profile)
    {
        case srtp_profile_id::aes128_cm_sha1_80:
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);

            srtp_crypto_policy_set_rtcp_default(&policy.rtcp);

            return {};

        case srtp_profile_id::aes128_cm_sha1_32:
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy.rtp);

            srtp_crypto_policy_set_rtcp_default(&policy.rtcp);

            return {};

        case srtp_profile_id::unknown:
            return make_error("srtp profile is unknown");
    }

    return make_error("srtp profile is unsupported");
}

srtp_master_key_and_salt make_master_key_and_salt(const std::array<uint8_t, k_srtp_aes128_master_key_size>& master_key,
                                                  const std::array<uint8_t, k_srtp_aes128_master_salt_size>& master_salt)
{
    srtp_master_key_and_salt key{};

    std::size_t offset = 0;

    std::copy_n(master_key.begin(), master_key.size(), key.begin());

    offset += master_key.size();

    std::copy_n(master_salt.begin(), master_salt.size(), key.begin() + static_cast<std::ptrdiff_t>(offset));

    return key;
}

std::expected<void, std::string> validate_packet_buffer(std::span<uint8_t> buffer, std::size_t packet_size)
{
    if (buffer.empty())
    {
        return make_error("srtp packet buffer is empty");
    }

    if (packet_size == 0)
    {
        return make_error("srtp packet size is zero");
    }

    if (packet_size > buffer.size())
    {
        return make_error("srtp packet size exceeds buffer size");
    }

    if (packet_size > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        return make_error("srtp packet size exceeds int range");
    }

    return {};
}

srtp_packet_result protect_packet(srtp_t native_handle, std::span<uint8_t> buffer, std::size_t packet_size, bool is_rtcp)
{
    if (native_handle == nullptr)
    {
        return make_error("srtp session is null");
    }

    auto validate_result = validate_packet_buffer(buffer, packet_size);

    if (!validate_result)
    {
        return std::unexpected(validate_result.error());
    }

    int size = static_cast<int>(packet_size);

    const srtp_err_status_t status =
        is_rtcp ? srtp_protect_rtcp(native_handle, buffer.data(), &size) : srtp_protect(native_handle, buffer.data(), &size);

    if (status != srtp_err_status_ok)
    {
        std::string message = is_rtcp ? "srtp protect rtcp failed: " : "srtp protect rtp failed: ";

        message.append(srtp_error_to_string(status));

        return std::unexpected(std::move(message));
    }

    if (size < 0)
    {
        return make_error("srtp protected packet size is negative");
    }

    const std::size_t output_size = static_cast<std::size_t>(size);

    if (output_size > buffer.size())
    {
        return make_error("srtp protected packet exceeds buffer size");
    }

    return output_size;
}

srtp_packet_result unprotect_packet(srtp_t native_handle, std::span<uint8_t> buffer, std::size_t packet_size, bool is_rtcp)
{
    if (native_handle == nullptr)
    {
        return make_error("srtp session is null");
    }

    auto validate_result = validate_packet_buffer(buffer, packet_size);

    if (!validate_result)
    {
        return std::unexpected(validate_result.error());
    }

    int size = static_cast<int>(packet_size);

    const srtp_err_status_t status =
        is_rtcp ? srtp_unprotect_rtcp(native_handle, buffer.data(), &size) : srtp_unprotect(native_handle, buffer.data(), &size);

    if (status != srtp_err_status_ok)
    {
        std::string message = is_rtcp ? "srtp unprotect rtcp failed: " : "srtp unprotect rtp failed: ";

        message.append(srtp_error_to_string(status));

        return std::unexpected(std::move(message));
    }

    if (size < 0)
    {
        return make_error("srtp unprotected packet size is negative");
    }

    return static_cast<std::size_t>(size);
}
}    // namespace

srtp_session::srtp_session(srtp_t native_handle) : native_handle_(native_handle) {}

srtp_session::~srtp_session() { reset(); }

srtp_session::srtp_session(srtp_session&& other) noexcept : native_handle_(std::exchange(other.native_handle_, nullptr)) {}

srtp_session& srtp_session::operator=(srtp_session&& other) noexcept
{
    if (this != &other)
    {
        reset();

        native_handle_ = std::exchange(other.native_handle_, nullptr);
    }

    return *this;
}

srtp_packet_result srtp_session::protect_rtp(std::span<uint8_t> buffer, std::size_t packet_size)
{
    return protect_packet(native_handle_, buffer, packet_size, false);
}

srtp_packet_result srtp_session::unprotect_rtp(std::span<uint8_t> buffer, std::size_t packet_size)
{
    return unprotect_packet(native_handle_, buffer, packet_size, false);
}

srtp_packet_result srtp_session::protect_rtcp(std::span<uint8_t> buffer, std::size_t packet_size)
{
    return protect_packet(native_handle_, buffer, packet_size, true);
}

srtp_packet_result srtp_session::unprotect_rtcp(std::span<uint8_t> buffer, std::size_t packet_size)
{
    return unprotect_packet(native_handle_, buffer, packet_size, true);
}

void srtp_session::reset()
{
    if (native_handle_ != nullptr)
    {
        srtp_dealloc(native_handle_);
        native_handle_ = nullptr;
    }
}

namespace
{
std::expected<srtp_t, std::string> make_srtp_native_handle(
    srtp_direction direction,
    srtp_profile_id profile,
    const std::array<uint8_t, k_srtp_aes128_master_key_size>& master_key,
    const std::array<uint8_t, k_srtp_aes128_master_salt_size>& master_salt)
{
    const srtp_err_status_t init_status = init_srtp_once();

    if (init_status != srtp_err_status_ok)
    {
        std::string message = "srtp init failed: ";
        message.append(srtp_error_to_string(init_status));
        return std::unexpected(std::move(message));
    }

    auto validate_result = validate_profile(profile);

    if (!validate_result)
    {
        return std::unexpected(validate_result.error());
    }

    srtp_policy_t policy{};
    policy.ssrc.type = make_ssrc_type(direction);
    policy.ssrc.value = 0;
    policy.window_size = 1024;
    policy.allow_repeat_tx = 1;
    policy.next = nullptr;

    auto policy_result = set_crypto_policy(profile, policy);

    if (!policy_result)
    {
        return std::unexpected(policy_result.error());
    }

    auto key = make_master_key_and_salt(master_key, master_salt);

    policy.key = key.data();

    srtp_t native_handle = nullptr;

    const srtp_err_status_t status = srtp_create(&native_handle, &policy);

    if (status != srtp_err_status_ok)
    {
        std::string message = "srtp create failed: ";
        message.append(srtp_error_to_string(status));
        return std::unexpected(std::move(message));
    }

    return native_handle;
}
}    // namespace

srtp_session_result make_inbound_srtp_session(const srtp_keying_material& material)
{
    auto native_handle = make_srtp_native_handle(srtp_direction::inbound,
                                                 material.profile,
                                                 material.client_write_master_key,
                                                 material.client_write_master_salt);

    if (!native_handle)
    {
        return std::unexpected(native_handle.error());
    }

    return srtp_session(*native_handle);
}

srtp_session_result make_outbound_srtp_session(const srtp_keying_material& material)
{
    auto native_handle = make_srtp_native_handle(srtp_direction::outbound,
                                                 material.profile,
                                                 material.server_write_master_key,
                                                 material.server_write_master_salt);

    if (!native_handle)
    {
        return std::unexpected(native_handle.error());
    }

    return srtp_session(*native_handle);
}

std::string srtp_direction_to_string(srtp_direction direction)
{
    switch (direction)
    {
        case srtp_direction::inbound:
            return "inbound";

        case srtp_direction::outbound:
            return "outbound";
    }

    return "unknown";
}

namespace
{
std::string srtp_error_to_string(srtp_err_status_t status)
{
    switch (status)
    {
        case srtp_err_status_ok:
            return "ok";

        case srtp_err_status_fail:
            return "fail";

        case srtp_err_status_bad_param:
            return "bad_param";

        case srtp_err_status_alloc_fail:
            return "alloc_fail";

        case srtp_err_status_dealloc_fail:
            return "dealloc_fail";

        case srtp_err_status_init_fail:
            return "init_fail";

        case srtp_err_status_terminus:
            return "terminus";

        case srtp_err_status_auth_fail:
            return "auth_fail";

        case srtp_err_status_cipher_fail:
            return "cipher_fail";

        case srtp_err_status_replay_fail:
            return "replay_fail";

        case srtp_err_status_replay_old:
            return "replay_old";

        case srtp_err_status_algo_fail:
            return "algo_fail";

        case srtp_err_status_no_such_op:
            return "no_such_op";

        case srtp_err_status_no_ctx:
            return "no_ctx";

        case srtp_err_status_cant_check:
            return "cant_check";

        case srtp_err_status_key_expired:
            return "key_expired";

        case srtp_err_status_socket_err:
            return "socket_err";

        case srtp_err_status_signal_err:
            return "signal_err";

        case srtp_err_status_nonce_bad:
            return "nonce_bad";

        case srtp_err_status_read_fail:
            return "read_fail";

        case srtp_err_status_write_fail:
            return "write_fail";

        case srtp_err_status_parse_err:
            return "parse_err";

        case srtp_err_status_encode_err:
            return "encode_err";

        case srtp_err_status_semaphore_err:
            return "semaphore_err";

        case srtp_err_status_pfkey_err:
            return "pfkey_err";

        case srtp_err_status_bad_mki:
            return "bad_mki";

        case srtp_err_status_pkt_idx_old:
            return "pkt_idx_old";

        case srtp_err_status_pkt_idx_adv:
            return "pkt_idx_adv";

        default:
            return "unknown";
    }
}
}    // namespace

bool is_srtp_replay_error(std::string_view error)
{
    return error.find("replay_fail") != std::string_view::npos || error.find("replay_old") != std::string_view::npos;
}
}    // namespace webrtc
