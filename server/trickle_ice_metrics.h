#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_METRICS_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_METRICS_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace webrtc
{
enum class trickle_ice_patch_content_kind
{
    kJson,
    kSdpfrag,
    kUnsupported
};

struct trickle_ice_metrics_snapshot
{
    uint64_t patch_requests = 0;
    uint64_t json_patch_requests = 0;
    uint64_t sdpfrag_patch_requests = 0;
    uint64_t unsupported_patch_requests = 0;

    uint64_t patch_success = 0;
    uint64_t patch_failed = 0;

    uint64_t session_not_found = 0;
    uint64_t parse_failed = 0;

    uint64_t candidates_received = 0;
    uint64_t candidates_accepted = 0;
    uint64_t candidates_rejected = 0;

    uint64_t end_of_candidates_received = 0;
    uint64_t end_of_candidates_accepted = 0;

    uint64_t candidate_bytes_received = 0;
};

class trickle_ice_metrics
{
   public:
    trickle_ice_metrics() = default;

    ~trickle_ice_metrics() = default;

    trickle_ice_metrics(const trickle_ice_metrics&) = delete;

    trickle_ice_metrics& operator=(const trickle_ice_metrics&) = delete;

    trickle_ice_metrics(trickle_ice_metrics&&) = delete;

    trickle_ice_metrics& operator=(trickle_ice_metrics&&) = delete;

   public:
    void record_patch_request(trickle_ice_patch_content_kind kind)
    {
        patch_requests_.fetch_add(1, std::memory_order_relaxed);

        switch (kind)
        {
            case trickle_ice_patch_content_kind::kJson:
            {
                json_patch_requests_.fetch_add(1, std::memory_order_relaxed);

                break;
            }

            case trickle_ice_patch_content_kind::kSdpfrag:
            {
                sdpfrag_patch_requests_.fetch_add(1, std::memory_order_relaxed);

                break;
            }

            case trickle_ice_patch_content_kind::kUnsupported:
            {
                unsupported_patch_requests_.fetch_add(1, std::memory_order_relaxed);

                break;
            }
        }
    }

    void record_patch_success() { patch_success_.fetch_add(1, std::memory_order_relaxed); }

    void record_patch_failed() { patch_failed_.fetch_add(1, std::memory_order_relaxed); }

    void record_session_not_found() { session_not_found_.fetch_add(1, std::memory_order_relaxed); }

    void record_parse_failed() { parse_failed_.fetch_add(1, std::memory_order_relaxed); }

    void record_candidate_batch(std::size_t candidate_count, std::size_t end_of_candidates_count, std::size_t candidate_bytes)
    {
        candidates_received_.fetch_add(static_cast<uint64_t>(candidate_count), std::memory_order_relaxed);

        end_of_candidates_received_.fetch_add(static_cast<uint64_t>(end_of_candidates_count), std::memory_order_relaxed);

        candidate_bytes_received_.fetch_add(static_cast<uint64_t>(candidate_bytes), std::memory_order_relaxed);
    }

    void record_candidate_accepted(bool end_of_candidates)
    {
        candidates_accepted_.fetch_add(1, std::memory_order_relaxed);

        if (end_of_candidates)
        {
            end_of_candidates_accepted_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void record_candidate_rejected() { candidates_rejected_.fetch_add(1, std::memory_order_relaxed); }

    [[nodiscard]]
    trickle_ice_metrics_snapshot snapshot() const
    {
        trickle_ice_metrics_snapshot result;

        result.patch_requests = patch_requests_.load(std::memory_order_relaxed);

        result.json_patch_requests = json_patch_requests_.load(std::memory_order_relaxed);

        result.sdpfrag_patch_requests = sdpfrag_patch_requests_.load(std::memory_order_relaxed);

        result.unsupported_patch_requests = unsupported_patch_requests_.load(std::memory_order_relaxed);

        result.patch_success = patch_success_.load(std::memory_order_relaxed);

        result.patch_failed = patch_failed_.load(std::memory_order_relaxed);

        result.session_not_found = session_not_found_.load(std::memory_order_relaxed);

        result.parse_failed = parse_failed_.load(std::memory_order_relaxed);

        result.candidates_received = candidates_received_.load(std::memory_order_relaxed);

        result.candidates_accepted = candidates_accepted_.load(std::memory_order_relaxed);

        result.candidates_rejected = candidates_rejected_.load(std::memory_order_relaxed);

        result.end_of_candidates_received = end_of_candidates_received_.load(std::memory_order_relaxed);

        result.end_of_candidates_accepted = end_of_candidates_accepted_.load(std::memory_order_relaxed);

        result.candidate_bytes_received = candidate_bytes_received_.load(std::memory_order_relaxed);

        return result;
    }

   private:
    std::atomic<uint64_t> patch_requests_{0};

    std::atomic<uint64_t> json_patch_requests_{0};

    std::atomic<uint64_t> sdpfrag_patch_requests_{0};

    std::atomic<uint64_t> unsupported_patch_requests_{0};

    std::atomic<uint64_t> patch_success_{0};

    std::atomic<uint64_t> patch_failed_{0};

    std::atomic<uint64_t> session_not_found_{0};

    std::atomic<uint64_t> parse_failed_{0};

    std::atomic<uint64_t> candidates_received_{0};

    std::atomic<uint64_t> candidates_accepted_{0};

    std::atomic<uint64_t> candidates_rejected_{0};

    std::atomic<uint64_t> end_of_candidates_received_{0};

    std::atomic<uint64_t> end_of_candidates_accepted_{0};

    std::atomic<uint64_t> candidate_bytes_received_{0};
};

inline trickle_ice_metrics& global_trickle_ice_metrics()
{
    static trickle_ice_metrics metrics;

    return metrics;
}

namespace trickle_ice_metrics_detail
{
inline void append_json_uint64(std::string& output, std::string_view name, uint64_t value, bool& first)
{
    if (!first)
    {
        output.push_back(',');
    }

    first = false;

    output.push_back('"');
    output.append(name);
    output.append("\":");
    output.append(std::to_string(value));
}

inline void append_metric_header(std::string& output, std::string_view name, std::string_view help, std::string_view type)
{
    output.append("# HELP ");
    output.append(name);
    output.push_back(' ');
    output.append(help);
    output.push_back('\n');

    output.append("# TYPE ");
    output.append(name);
    output.push_back(' ');
    output.append(type);
    output.push_back('\n');
}

inline void append_metric_value(std::string& output, std::string_view name, uint64_t value)
{
    output.append(name);
    output.push_back(' ');
    output.append(std::to_string(value));
    output.push_back('\n');
}
}    // namespace trickle_ice_metrics_detail

[[nodiscard]]
inline std::string trickle_ice_metrics_snapshot_to_json(const trickle_ice_metrics_snapshot& snapshot)
{
    std::string output;

    output.reserve(768);

    bool first = true;

    output.push_back('{');

    trickle_ice_metrics_detail::append_json_uint64(output, "patch_requests", snapshot.patch_requests, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "json_patch_requests", snapshot.json_patch_requests, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "sdpfrag_patch_requests", snapshot.sdpfrag_patch_requests, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "unsupported_patch_requests", snapshot.unsupported_patch_requests, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "patch_success", snapshot.patch_success, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "patch_failed", snapshot.patch_failed, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "session_not_found", snapshot.session_not_found, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "parse_failed", snapshot.parse_failed, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "candidates_received", snapshot.candidates_received, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "candidates_accepted", snapshot.candidates_accepted, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "candidates_rejected", snapshot.candidates_rejected, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "end_of_candidates_received", snapshot.end_of_candidates_received, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "end_of_candidates_accepted", snapshot.end_of_candidates_accepted, first);

    trickle_ice_metrics_detail::append_json_uint64(output, "candidate_bytes_received", snapshot.candidate_bytes_received, first);

    output.push_back('}');

    return output;
}

[[nodiscard]]
inline std::string trickle_ice_metrics_snapshot_to_prometheus(const trickle_ice_metrics_snapshot& snapshot)
{
    std::string output;

    output.reserve(8192);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_patch_requests_total", "total trickle ice patch requests", "counter");

    trickle_ice_metrics_detail::append_metric_value(output, "simplewebrtc_trickle_ice_patch_requests_total", snapshot.patch_requests);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_patch_json_requests_total", "total trickle ice json patch requests", "counter");

    trickle_ice_metrics_detail::append_metric_value(output, "simplewebrtc_trickle_ice_patch_json_requests_total", snapshot.json_patch_requests);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_patch_sdpfrag_requests_total", "total trickle ice sdp fragment patch requests", "counter");

    trickle_ice_metrics_detail::append_metric_value(output, "simplewebrtc_trickle_ice_patch_sdpfrag_requests_total", snapshot.sdpfrag_patch_requests);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_patch_unsupported_requests_total", "total unsupported trickle ice patch requests", "counter");

    trickle_ice_metrics_detail::append_metric_value(
        output, "simplewebrtc_trickle_ice_patch_unsupported_requests_total", snapshot.unsupported_patch_requests);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_patch_success_total", "total successful trickle ice patch requests", "counter");

    trickle_ice_metrics_detail::append_metric_value(output, "simplewebrtc_trickle_ice_patch_success_total", snapshot.patch_success);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_patch_failed_total", "total failed trickle ice patch requests", "counter");

    trickle_ice_metrics_detail::append_metric_value(output, "simplewebrtc_trickle_ice_patch_failed_total", snapshot.patch_failed);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_session_not_found_total", "total trickle ice patch requests for missing sessions", "counter");

    trickle_ice_metrics_detail::append_metric_value(output, "simplewebrtc_trickle_ice_session_not_found_total", snapshot.session_not_found);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_parse_failed_total", "total trickle ice patch parse failures", "counter");

    trickle_ice_metrics_detail::append_metric_value(output, "simplewebrtc_trickle_ice_parse_failed_total", snapshot.parse_failed);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_candidates_received_total", "total trickle ice candidates received", "counter");

    trickle_ice_metrics_detail::append_metric_value(output, "simplewebrtc_trickle_ice_candidates_received_total", snapshot.candidates_received);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_candidates_accepted_total", "total trickle ice candidates accepted", "counter");

    trickle_ice_metrics_detail::append_metric_value(output, "simplewebrtc_trickle_ice_candidates_accepted_total", snapshot.candidates_accepted);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_candidates_rejected_total", "total trickle ice candidates rejected", "counter");

    trickle_ice_metrics_detail::append_metric_value(output, "simplewebrtc_trickle_ice_candidates_rejected_total", snapshot.candidates_rejected);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_end_of_candidates_received_total", "total trickle ice end of candidates markers received", "counter");

    trickle_ice_metrics_detail::append_metric_value(
        output, "simplewebrtc_trickle_ice_end_of_candidates_received_total", snapshot.end_of_candidates_received);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_end_of_candidates_accepted_total", "total trickle ice end of candidates markers accepted", "counter");

    trickle_ice_metrics_detail::append_metric_value(
        output, "simplewebrtc_trickle_ice_end_of_candidates_accepted_total", snapshot.end_of_candidates_accepted);

    trickle_ice_metrics_detail::append_metric_header(
        output, "simplewebrtc_trickle_ice_candidate_bytes_received_total", "total trickle ice candidate bytes received", "counter");

    trickle_ice_metrics_detail::append_metric_value(
        output, "simplewebrtc_trickle_ice_candidate_bytes_received_total", snapshot.candidate_bytes_received);

    return output;
}
}    // namespace webrtc

#endif
