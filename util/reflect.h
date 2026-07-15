#ifndef SIMPLE_WEBRTC_UTIL_REFLECT_H
#define SIMPLE_WEBRTC_UTIL_REFLECT_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <boost/preprocessor/seq/for_each.hpp>

namespace webrtc
{
inline rapidjson::SizeType rapidjson_size(std::size_t value)
{
    if (value > static_cast<std::size_t>(std::numeric_limits<rapidjson::SizeType>::max()))
    {
        throw std::length_error("json string is too large");
    }

    return static_cast<rapidjson::SizeType>(value);
}
struct JsonReader
{
    rapidjson::Value* m;

    JsonReader(rapidjson::Value* m) : m(m) {}
    void iterArray(const std::function<void()>& fn);
    void member(const char* name, const std::function<void()>& fn);
    std::string getString();
};

struct JsonWriter
{
    using W = rapidjson::Writer<rapidjson::StringBuffer, rapidjson::UTF8<char>, rapidjson::UTF8<char>, rapidjson::CrtAllocator, 0>;

    W* m;

    JsonWriter(W* m) : m(m) {}
    void startArray();
    void endArray();
    void startObject();
    void endObject();
    void key(const char* name);
    void string(const char* s, size_t len);
};

inline std::string JsonReader::getString() { return m->GetString(); }
inline void JsonWriter::startArray() { m->StartArray(); }
inline void JsonWriter::endArray() { m->EndArray(); }
inline void JsonWriter::startObject() { m->StartObject(); }
inline void JsonWriter::endObject() { m->EndObject(); }
inline void JsonWriter::key(const char* name) { m->Key(name); }
inline void JsonWriter::string(const char* s, size_t len) { m->String(s, rapidjson_size(len)); }
inline void reflect(JsonReader& vis, bool& v)
{
    if (!vis.m->IsBool())
    {
        throw std::invalid_argument("bool");
    }
    v = vis.m->GetBool();
}
inline void reflect(JsonReader& vis, unsigned char& v)
{
    if (!vis.m->IsInt())
    {
        throw std::invalid_argument("uint8_t");
    }
    v = (uint8_t)vis.m->GetInt();
}
inline void reflect(JsonReader& vis, short& v)
{
    if (!vis.m->IsInt())
    {
        throw std::invalid_argument("short");
    }
    v = (short)vis.m->GetInt();
}
inline void reflect(JsonReader& vis, unsigned short& v)
{
    if (!vis.m->IsInt())
    {
        throw std::invalid_argument("unsigned short");
    }
    v = (unsigned short)vis.m->GetInt();
}
inline void reflect(JsonReader& vis, int8_t& v)
{
    if (!vis.m->IsInt())
    {
        throw std::invalid_argument("int8_t");
    }

    const int value = vis.m->GetInt();

    if (value < static_cast<int>(std::numeric_limits<int8_t>::min()) || value > static_cast<int>(std::numeric_limits<int8_t>::max()))
    {
        throw std::out_of_range("int8_t");
    }
    v = static_cast<int8_t>(value);
}
inline void reflect(JsonReader& vis, int& v)
{
    if (!vis.m->IsInt())
    {
        throw std::invalid_argument("int");
    }
    v = vis.m->GetInt();
}
inline void reflect(JsonReader& vis, unsigned& v)
{
    if (!vis.m->IsUint64())
    {
        throw std::invalid_argument("unsigned");
    }
    v = (unsigned)vis.m->GetUint64();
}
inline void reflect(JsonReader& vis, long& v)
{
    if (!vis.m->IsInt64())
    {
        throw std::invalid_argument("long");
    }
    v = (long)vis.m->GetInt64();
}
inline void reflect(JsonReader& vis, unsigned long& v)
{
    if (!vis.m->IsUint64())
    {
        throw std::invalid_argument("unsigned long");
    }
    v = (unsigned long)vis.m->GetUint64();
}
inline void reflect(JsonReader& vis, long long& v)
{
    if (!vis.m->IsInt64())
    {
        throw std::invalid_argument("long long");
    }
    v = vis.m->GetInt64();
}
inline void reflect(JsonReader& vis, unsigned long long& v)
{
    if (!vis.m->IsUint64())
    {
        throw std::invalid_argument("unsigned long long");
    }
    v = vis.m->GetUint64();
}
inline void reflect(JsonReader& vis, double& v)
{
    if (!vis.m->IsDouble())
    {
        throw std::invalid_argument("double");
    }
    v = vis.m->GetDouble();
}
inline void reflect(JsonReader& vis, std::string& v)
{
    if (!vis.m->IsString())
    {
        throw std::invalid_argument("string");
    }
    v = vis.getString();
}
inline void reflect(JsonWriter& vis, bool& v) { vis.m->Bool(v); }
inline void reflect(JsonWriter& vis, unsigned char& v) { vis.m->Int(v); }
inline void reflect(JsonWriter& vis, short& v) { vis.m->Int(v); }
inline void reflect(JsonWriter& vis, unsigned short& v) { vis.m->Int(v); }
inline void reflect(JsonWriter& vis, int& v) { vis.m->Int(v); }
inline void reflect(JsonWriter& vis, int8_t& v) { vis.m->Int(v); }
inline void reflect(JsonWriter& vis, unsigned& v) { vis.m->Uint64(v); }
inline void reflect(JsonWriter& vis, long& v) { vis.m->Int64(v); }
inline void reflect(JsonWriter& vis, unsigned long& v) { vis.m->Uint64(v); }
inline void reflect(JsonWriter& vis, long long& v) { vis.m->Int64(v); }
inline void reflect(JsonWriter& vis, unsigned long long& v) { vis.m->Uint64(v); }
inline void reflect(JsonWriter& vis, double& v) { vis.m->Double(v); }
inline void reflect(JsonWriter& vis, std::string& v) { vis.string(v.c_str(), v.size()); }
// std::vector
template <typename T>
inline void reflect(JsonReader& vis, std::vector<T>& v)
{
    vis.iterArray(
        [&]()
        {
            v.emplace_back();
            reflect(vis, v.back());
        });
}
template <typename T>
inline void reflect(JsonWriter& vis, std::vector<T>& v)
{
    vis.startArray();
    for (auto& it : v)
    {
        reflect(vis, it);
    }
    vis.endArray();
}


inline void reflectMemberStart(JsonReader& vis)
{
    if (!vis.m->IsObject())
    {
        throw std::invalid_argument("object");
    }
}

inline void reflectMemberStart(JsonWriter& vis) { vis.startObject(); }

inline void reflectMemberEnd(JsonReader& /*unused*/) {}
inline void reflectMemberEnd(JsonWriter& vis) { vis.endObject(); }

template <typename T>
inline void reflectMember(JsonReader& vis, const char* name, T& v)
{
    vis.member(name, [&]() { reflect(vis, v); });
}
template <typename T>
inline void reflectMember(JsonWriter& vis, const char* name, T& v)
{
    vis.key(name);
    reflect(vis, v);
}
inline void JsonReader::iterArray(const std::function<void()>& fn)
{
    if (!m->IsArray())
    {
        throw std::invalid_argument("array");
    }
    for (auto& entry : m->GetArray())
    {
        auto* saved = m;
        m = &entry;
        fn();
        m = saved;
    }
}
inline void JsonReader::member(const char* name, const std::function<void()>& fn)
{
    auto it = m->FindMember(name);
    if (it != m->MemberEnd())
    {
        auto* saved = m;
        m = &it->value;
        fn();
        m = saved;
    }
}

#define REFLECT_MEMBER(name) reflectMember(vis, #name, v.name)

#define _MAPPABLE_REFLECT_MEMBER(unuse, type, name) REFLECT_MEMBER(name);

#define REFLECT_STRUCT(type, ...)                                       \
    template <typename Vis>                                             \
    void reflect(Vis& vis, type& v)                                     \
    {                                                                   \
        reflectMemberStart(vis);                                        \
        BOOST_PP_SEQ_FOR_EACH(_MAPPABLE_REFLECT_MEMBER, _, __VA_ARGS__) \
        reflectMemberEnd(vis);                                          \
    }

template <typename T>
inline bool deserialize_struct(T& t, const std::string& msg)
{
    try
    {
        rapidjson::Document reader;
        const rapidjson::ParseResult ok = reader.Parse(msg.data());
        if (!ok)
        {
            return false;
        }

        JsonReader json_reader{&reader};
        reflect(json_reader, t);
    }
    catch (...)
    {
        return false;
    }
    return true;
}

template <typename T>
inline bool deserialize_struct(T& t, const char* msg, std::size_t lenght)
{
    try
    {
        rapidjson::Document reader;
        const rapidjson::ParseResult ok = reader.Parse(msg, lenght);
        if (!ok)
        {
            return false;
        }
        JsonReader json_reader{&reader};
        reflect(json_reader, t);
    }
    catch (...)
    {
        return false;
    }
    return true;
}

template <typename T>
inline std::string serialize_struct(T& t)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    JsonWriter json_writer(&writer);
    reflect(json_writer, t);
    return sb.GetString();
}
template <typename T>
inline std::string serialize_struct(const T& t)
{
    auto Temp = const_cast<T&>(t);
    return serialize_struct(Temp);
}

}    // namespace webrtc

#endif
