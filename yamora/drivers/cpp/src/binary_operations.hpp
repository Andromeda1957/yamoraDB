#pragma once
#include "binary_wire.hpp"
#include "json.hpp"
#include <set>

namespace yamora::operation_detail {
using binary_detail::require;
inline std::string media(std::string_view value) {
  std::string result(value.substr(0, value.find(';')));
  for (auto &c : result) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a'-'A'));
  return result;
}
inline std::string after(std::string_view target) {
  auto start = target.find('?'); if (start == std::string_view::npos) return {};
  target.remove_prefix(start+1);
  while (!target.empty()) {
    auto end = target.find('&'); auto pair = target.substr(0,end);
    if (pair.substr(0,6) == "after=") return std::string(pair.substr(6));
    if (end == std::string_view::npos) break;
    target.remove_prefix(end+1);
  }
  return {};
}
inline bool token(std::string_view value) {
  return value.size() == 52 && value.substr(0,3) == "v1." && value[35] == '.' &&
    binary_detail::hex(value.substr(3,32),32) && binary_detail::hex(value.substr(36),16);
}
inline bool document(std::string_view target) {
  constexpr std::string_view prefix="/v1/collections/", middle="/documents/";
  if (target.substr(0,prefix.size()) != prefix) return false;
  target.remove_prefix(prefix.size()); auto split=target.find(middle);
  return split != std::string_view::npos && binary_detail::name(target.substr(0,split)) && binary_detail::name(target.substr(split+middle.size()));
}
inline void input(std::string_view method,std::string_view target,std::string_view type,std::string_view source,const BinaryOptions &options,bool feed) {
  using namespace binary_detail;
  validate(BinaryMethod::get,"valid","valid",{},options);
  bool query=false;
  for (auto prefix : {std::string_view("/v1/query/"),std::string_view("/v1/aggregate/"),std::string_view("/v1/search/")})
    if (target.substr(0,prefix.size()) == prefix && name(target.substr(prefix.size()))) query=true;
  bool change=target == "/v1/changes" || target.substr(0,12) == "/v1/changes?" || target.substr(0,19) == "/v1/changes/stream?";
  auto base=media(type);
  if (target.empty() || !ascii(target,511) || !ascii(type,95) || source.size()>max_document_bytes ||
    !((method=="GET" && change) || (method=="POST" && (query || target=="/v1/transactions")) || (method=="PATCH" && document(target))) ||
    (method=="GET" ? !source.empty() || !type.empty() : base!="application/json" && base!="application/yaml" && base!="text/yaml") ||
    feed != (target.substr(0,19)=="/v1/changes/stream?")) invalid();
}
inline unsigned negotiate(std::string_view hello, unsigned local) {
  using namespace binary_detail;
  require(hello.size()==12);
  auto minimum=integer(hello.substr(0,2)), maximum=integer(hello.substr(2,2));
  auto cap=integer(hello.substr(4,4)), streams=integer(hello.substr(8,4));
  require(minimum>=1 && maximum>=minimum && cap>=4096 && cap<=1048576 && streams>=1 && streams<=128);
  if (minimum>2 || maximum<2) throw BinaryUnsupportedPeerError();
  return static_cast<unsigned>(std::min<std::uint64_t>(local,cap));
}
inline std::string metadata(std::string_view method,std::string_view target,std::string_view type,std::size_t length,const BinaryOptions &options,std::string_view bearer,unsigned timeout) {
  using namespace binary_detail;
  std::string fields;unsigned count=0;
  auto field=[&](unsigned id,std::string_view bytes){ fields+=number(id,2)+number(bytes.size(),2);fields.append(bytes);++count; };
  field(1,number(method=="GET"?1:method=="POST"?5:6,1));field(2,target);field(3,type);field(4,number(length,8));
  if (!bearer.empty()) field(5,"Bearer "+std::string(bearer));
  if (options.if_match) field(6,*options.if_match);
  if (options.if_none_match) field(7,*options.if_none_match);
  if (options.request_id) {
    std::string bytes;for (std::size_t i=0;i<32;i+=2) bytes+=static_cast<char>(std::stoul(options.request_id->substr(i,2),nullptr,16));field(8,bytes);
  }
  field(9,number(timeout,4));
  if (fields.size()+4>max_metadata) invalid();
  return number(2,2)+number(count,2)+fields;
}
inline void correlate(const binary_detail::Reply &reply,std::string_view method,std::string_view target,const BinaryOptions &options,bool feed) {
  const auto &r=reply.value;
  require(r.request_id==options.request_id && reply.length==r.representation_length);
  require(r.status>=400 ? !reply.streaming && reply.length<=4096 : r.status==200 && feed==reply.streaming);
  require(media(r.content_type)==(reply.streaming?"application/x-ndjson":"application/json"));
  require(!(method=="PATCH" || target=="/v1/transactions") || reply.length<=4096);
  require((r.status==401)==r.authenticate.has_value() && (r.status==405)==r.allow.has_value());
  if (method=="PATCH") {
    target.remove_prefix(16); // /v1/collections/
    auto split=target.find("/documents/");
    require((!r.collection || *r.collection==target.substr(0,split)) && (!r.document || *r.document==target.substr(split+11)));
  } else require(!r.collection && !r.document && r.etag.empty());
}
struct Page { std::string after;bool terminal=false; };
inline Page page(const detail::Json &p,std::string_view after) {
  using detail::Json;
  if (auto terminal=p.optional("terminal")) {
    require(p.fields.size()==4 && terminal->boolean_value() && p.get("status").uint()>=400 && p.get("status").uint()<=599 && p.get("after").str()==after && p.get("detail").type==Json::object);
    return {std::string(after),true};
  }
  const auto &next=p.get("next_after").str(), &tip=p.get("checkpoint").str(), &oldest=p.get("oldest_after").str();
  require(token(next) && token(tip) && token(oldest) && binary_detail::hex(p.get("revision").str(),16));
  require(next.substr(0,36)==tip.substr(0,36) && oldest.substr(0,36)==tip.substr(0,36) && oldest<=next && next<=tip && p.get("has_more").boolean_value()==(next<tip));
  require(after.empty() || (token(after) && after.substr(0,36)==std::string_view(next).substr(0,36) && after<=std::string_view(next)));
  const auto &transactions=p.get("transactions").list();require(transactions.size()<=100 && (!after.empty() || transactions.empty()));
  std::string previous(after),revision;
  for (const auto &tx:transactions) {
    const auto &cursor=tx.get("token").str(), &r=tx.get("revision").str(), &before=tx.get("previous_revision").str();
    require(token(cursor) && cursor.substr(0,36)==tip.substr(0,36) && cursor>previous && cursor<=tip && binary_detail::hex(r,16) && binary_detail::hex(before,16) && (revision.empty() || revision==before));
    const auto &operations=tx.get("operations").list();require(operations.size()<=256 && (!tx.get("resnapshot_required").boolean_value() || operations.empty()));
    std::set<std::string> seen; std::size_t bytes=0;
    for (const auto &op:operations) {
      const auto &collection=op.get("collection").str();require(binary_detail::name(collection));
      auto doc=op.optional("document");std::string document=doc?doc->str():"";require(seen.insert(collection+"/"+document).second);
      if (!doc) require(op.fields.size()==2 && op.get("create_collection").boolean_value());
      else { require(binary_detail::name(document) && op.fields.size()==3); auto put=op.optional("put"), erased=op.optional("delete");
        require((put!=nullptr)!=(erased!=nullptr));
        if (put) {auto n=put->str().size();require(n>0 && n<=max_document_bytes-bytes);bytes+=n;}
        else require(erased->boolean_value());
      }
    }
    previous=cursor;revision=r;
  }
  require(transactions.empty()? !p.get("has_more").boolean_value() && (after.empty() || after==next) : previous==next);
  return {next,false};
}
inline detail::Json json(std::string_view body,const detail::Control &control,unsigned depth_limit=80) {
  // The wire envelope surrounds a native depth64 value; ordinary decode stays64.
  binary_detail::utf8(body,control);auto result=detail::JsonParser(body,control,depth_limit).decode();require(result.type==detail::Json::object);return result;
}
inline void semantics(const binary_detail::Reply &reply,std::string_view method,std::string_view target,std::string_view type,std::string_view source,const detail::Control &control) {
  auto p=json(reply.value.body,control);const auto &r=reply.value;
  if (r.status>=400) {require(p.fields.size()==1);auto code=p.get("error").str();require(!code.empty() && code.size()<=128 && std::all_of(code.begin(),code.end(),[](char c){return (c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_';}));return;}
  require(p.get("revision").str()==r.revision);
  if (method=="PATCH") {
    target.remove_prefix(16);auto split=target.find("/documents/");
    require(p.fields.size()==5 && p.get("status").str()=="stored" && p.get("collection").str()==target.substr(0,split) && p.get("document").str()==target.substr(split+11) && binary_detail::hex(p.get("etag").str(),16) && p.get("etag").str()==r.etag);
  } else if (target=="/v1/transactions") {
    auto count=p.get("operations").uint();
    require(p.fields.size()==3 && p.get("status").str()=="committed" && count>=1 && count<=128);
    if (media(type)=="application/json") require(json(source,control,64).get("operations").list().size()==count);
  }
  else if (target.substr(0,11)=="/v1/changes") (void)page(p,after(target));
  control.check();
}
} // namespace yamora::operation_detail
