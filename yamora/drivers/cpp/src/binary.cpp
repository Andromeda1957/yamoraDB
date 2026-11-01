#include "binary_tls.hpp"
#include "binary_operations.hpp"
#include <condition_variable>
#include <mutex>
#include <type_traits>

namespace yamora {
static_assert(std::is_nothrow_copy_constructible_v<BinaryOperationError>);
static_assert(
    std::is_nothrow_copy_constructible<BinaryUncertainWriteError>::value,
    "uncertainty propagation must copy without allocating");
struct BinaryEnvelope::Data {
  const BinaryMethod method;
  const std::string collection, document, source;
  const BinaryOptions options;
  Data(BinaryMethod m, std::string c, std::string d, std::string s,
       BinaryOptions o)
      : method(m), collection(std::move(c)), document(std::move(d)),
        source(std::move(s)), options(std::move(o)) {}
};
BinaryMethod BinaryEnvelope::method() const noexcept { return data_->method; }
std::string BinaryEnvelope::collection() const { return data_->collection; }
std::string BinaryEnvelope::document() const { return data_->document; }
std::string BinaryEnvelope::source() const { return data_->source; }
BinaryOptions BinaryEnvelope::options() const { return data_->options; }
BinaryUncertainWriteError::BinaryUncertainWriteError(BinaryEnvelope envelope,
                                                     ErrorKind kind, int status)
    : Error(kind,
            "yamora: binary write outcome uncertain; retain original envelope",
            status, true),
      envelope_(std::move(envelope)) {}
struct BinaryClient::Impl {
  sockaddr_in endpoint;
  const std::string identity;
  const std::chrono::milliseconds timeout;
  const std::size_t frame, slots;
  binary_detail::Context tls;
  std::mutex mutex;
  std::condition_variable changed;
  std::size_t active = 0;
  explicit Impl(const BinaryConfig &c)
      : endpoint(binary_detail::address(c.host, c.port)), identity([&c] {
          binary_detail::server_identity(c.server_identity);
          return c.server_identity;
        }()),
        timeout(c.timeout), frame(c.max_frame_bytes),
        slots(c.max_concurrent_calls), tls(nullptr, SSL_CTX_free) {
    if (timeout.count() < 1 || timeout.count() > 30000 || frame < 4096 ||
        frame > 65536 || slots < 1 || slots > 4)
      binary_detail::invalid();
    tls = binary_detail::context(c);
  }
  struct Admission {
    Impl &owner;
    Admission(Impl &o, const detail::Control &control) : owner(o) {
      std::unique_lock<std::mutex> lock(owner.mutex);
      for (;;) {
        control.check();
        if (owner.active < owner.slots) {
          ++owner.active;
          return;
        }
        owner.changed.wait_for(lock, std::chrono::milliseconds(5));
      }
    }
    ~Admission() {
      {
        std::lock_guard<std::mutex> lock(owner.mutex);
        --owner.active;
      }
      owner.changed.notify_one();
    }
  };
};
BinaryClient::BinaryClient(const BinaryConfig &config)
    : impl_(std::make_shared<Impl>(config)) {}
BinaryResponse BinaryClient::get(std::string_view c, std::string_view d,
                                 std::string_view token, const BinaryOptions &o,
                                 const RequestOptions &r) const {
  return call(BinaryMethod::get, c, d, {}, token, o, r, nullptr);
}
BinaryResponse BinaryClient::head(std::string_view c, std::string_view d,
                                  std::string_view token,
                                  const BinaryOptions &o,
                                  const RequestOptions &r) const {
  return call(BinaryMethod::head, c, d, {}, token, o, r, nullptr);
}
BinaryResponse BinaryClient::put(std::string_view c, std::string_view d,
                                 std::string_view s, std::string_view token,
                                 const BinaryOptions &o,
                                 const RequestOptions &r) const {
  return call(BinaryMethod::put, c, d, s, token, o, r, nullptr);
}
BinaryResponse BinaryClient::erase(std::string_view c, std::string_view d,
                                   std::string_view token,
                                   const BinaryOptions &o,
                                   const RequestOptions &r) const {
  return call(BinaryMethod::erase, c, d, {}, token, o, r, nullptr);
}
BinaryResponse BinaryClient::execute(const BinaryEnvelope &e,
                                     std::string_view token,
                                     const RequestOptions &r) const {
  const auto &v = *e.data_;
  return call(v.method, v.collection, v.document, v.source, token, v.options, r,
              &e);
}
BinaryResponse
BinaryClient::call(BinaryMethod method, std::string_view collection,
                   std::string_view document, std::string_view source,
                   std::string_view bearer, const BinaryOptions &options,
                   const RequestOptions &request,
                   const BinaryEnvelope *replay) const {
  using namespace binary_detail;
  const auto start = detail::Control::Clock::now();
  if (request.timeout.count() < 0)
    invalid();
  auto budget = request.timeout.count() > 0
                    ? std::min(request.timeout, impl_->timeout)
                    : impl_->timeout;
  const detail::Control control{start + budget, request.cancellation};
  Impl::Admission admission(*impl_, control);
  // Waiters retain only borrowed input; not even a source copy is made until
  // admission. Callers must synchronize their own input until return.
  control.check();
  validate(method, collection, document, source, options);
  if (bearer.size() > 512 ||
      !std::all_of(bearer.begin(), bearer.end(),
                   [](unsigned char c) { return c >= 33 && c <= 126; }))
    invalid();
  const std::string token(bearer);
  BinaryOptions owned_options = options;
  const bool mutation =
      method == BinaryMethod::put || method == BinaryMethod::erase;
  if (mutation && !owned_options.request_id)
    owned_options.request_id = random_id();
  auto data = replay
                  ? replay->data_
                  : std::make_shared<const BinaryEnvelope::Data>(
                        method, std::string(collection), std::string(document),
                        freeze(source, control), std::move(owned_options));
  const BinaryEnvelope envelope(data);
  if (method == BinaryMethod::put) {
    try {
      utf8(data->source, control);
    } catch (const Error &e) {
      if (e.kind() == ErrorKind::protocol)
        invalid();
      throw;
    }
  }
  control.check();
  // Construct the runtime_error message while failure still precedes dispatch.
  // Handler paths only set scalars and copy this exception's shared immutable
  // envelope/message; C++ exception ABI storage remains the runtime's concern.
  std::optional<BinaryUncertainWriteError> uncertainty;
  if (mutation)
    uncertainty.emplace(envelope, ErrorKind::transport);
  bool dispatched = false;
  try {
    Connection connection(control);
    connection.connect(impl_->endpoint, impl_->tls.get(), impl_->identity);
    connection.send(hello, 0,
                    number(1, 2) + number(1, 2) + number(impl_->frame, 4) +
                        number(1, 4));
    auto hello_reply = connection.receive(impl_->frame);
    require(hello_reply.first.kind == hello);
    auto cap = negotiate(hello_reply.second, impl_->frame);
    control.check();
    auto remaining = std::chrono::ceil<std::chrono::milliseconds>(
                         control.deadline - detail::Control::Clock::now())
                         .count();
    auto metadata = request_metadata(
        method, data->collection, data->document, data->source.size(),
        data->options, token,
        static_cast<unsigned>(std::clamp<std::int64_t>(remaining, 1, 30000)));
    control.check();
    dispatched = true; // first attempted REQUEST byte makes mutations ambiguous
    connection.send(binary_detail::request, 1, metadata);
    for (std::size_t offset = 0; offset < data->source.size(); offset += cap)
      connection.send(binary_detail::data, 1,
                      std::string_view(data->source).substr(offset, cap));
    connection.send(end, 1);
    unsigned pings = 0;
    auto receive = [&]() {
      for (;;) {
        auto frame = connection.receive(cap);
        if (frame.first.kind == ping) {
          require(++pings <= 4);
          connection.send(pong, 0, frame.second);
          continue;
        }
        if (frame.first.kind == error) {
          require(integer(frame.second) != 0);
          transport();
        }
        if (frame.first.kind == goaway)
          transport();
        return frame;
      }
    };
    auto first = receive();
    require(first.first.kind == response);
    auto reply = response_metadata(first.second);
    correlate(reply, method, data->collection, data->document, data->options);
    reply.value.body.reserve(static_cast<std::size_t>(reply.length));
    for (;;) {
      auto frame = receive();
      if (frame.first.kind == end) {
        require(reply.value.body.size() == reply.length);
        break;
      }
      require(frame.first.kind == binary_detail::data &&
              frame.second.size() <= reply.length - reply.value.body.size());
      reply.value.body += frame.second;
    }
    semantics(reply, method, data->collection, data->document, data->source,
              control);
    control.check();
    if (reply.value.status >= 400)
      throw Error(ErrorKind::http, "yamora: binary native request rejected",
                  reply.value.status);
    return std::move(reply.value);
  } catch (const Error &e) {
    if (dispatched && mutation &&
        (e.kind() != ErrorKind::http || e.status() == 408 ||
         e.status() >= 500)) {
      uncertainty->failure(e.kind(), e.status());
      throw *uncertainty;
    }
    throw;
  } catch (const std::bad_alloc &) {
    if (dispatched && mutation) {
      uncertainty->failure(ErrorKind::allocation);
      throw *uncertainty;
    }
    throw Error(ErrorKind::allocation, "yamora: binary allocation failed");
  }
}

struct BinaryOperation::Data {
  const std::string method,target,type,source;
  const BinaryOptions options;
  Data(std::string m,std::string t,std::string y,std::string s,BinaryOptions o)
    :method(std::move(m)),target(std::move(t)),type(std::move(y)),source(std::move(s)),options(std::move(o)){}
};
std::string BinaryOperation::method() const{return data_->method;}
std::string BinaryOperation::target() const{return data_->target;}
std::string BinaryOperation::content_type() const{return data_->type;}
std::string BinaryOperation::source() const{return data_->source;}
BinaryOptions BinaryOperation::options() const{return data_->options;}
BinaryResponse BinaryClient::operation(std::string_view method,std::string_view target,std::string_view type,std::string_view source,std::string_view bearer,const BinaryOptions &options,const RequestOptions &request) const {
  return operation_call(method,target,type,source,bearer,options,request,nullptr).response;
}
BinaryFeedResult BinaryClient::feed(std::string_view target,const std::function<void(std::string_view)> &consume,std::string_view bearer,const BinaryOptions &options,const RequestOptions &request) const {
  if (!consume) binary_detail::invalid();
  return operation_call("GET",target,{}, {},bearer,options,request,&consume);
}
BinaryFeedResult BinaryClient::operation_call(std::string_view method,std::string_view target,std::string_view type,std::string_view source,std::string_view bearer,const BinaryOptions &options,const RequestOptions &request,const std::function<void(std::string_view)> *consume) const {
  using namespace binary_detail;
  const auto start=detail::Control::Clock::now();
  if (request.timeout.count()<0) invalid();
  auto budget=request.timeout.count()>0?std::min(request.timeout,impl_->timeout):impl_->timeout;
  const detail::Control control{start+budget,request.cancellation};
  Impl::Admission admission(*impl_,control);
  operation_detail::input(method,target,type,source,options,consume!=nullptr);
  if (bearer.size()>512 || !std::all_of(bearer.begin(),bearer.end(),[](unsigned char c){return c>=33&&c<=126;})) invalid();
  std::string token(bearer);auto owned=options;
  if (!owned.request_id) owned.request_id=random_id();
  const BinaryOperation envelope(std::make_shared<const BinaryOperation::Data>(std::string(method),std::string(target),std::string(type),freeze(source,control),std::move(owned)));
  const auto &op=*envelope.data_;
  const bool mutation=op.method=="PATCH" || op.target=="/v1/transactions";
  BinaryOperationError failure(envelope,operation_detail::after(op.target));
  bool dispatched=false;
  try {
    control.check();Connection connection(control);connection.connect(impl_->endpoint,impl_->tls.get(),impl_->identity);
    connection.send(hello,0,number(1,2)+number(2,2)+number(impl_->frame,4)+number(1,4));
    auto peer=connection.receive(impl_->frame);require(peer.first.kind==hello);
    auto cap=operation_detail::negotiate(peer.second,static_cast<unsigned>(impl_->frame));
    control.check();auto remaining=std::chrono::ceil<std::chrono::milliseconds>(control.deadline-detail::Control::Clock::now()).count();
    auto metadata=operation_detail::metadata(op.method,op.target,op.type,op.source.size(),op.options,token,static_cast<unsigned>(std::clamp<std::int64_t>(remaining,1,30000)));
    control.check();dispatched=true;
    connection.send(binary_detail::request,1,metadata);
    for(std::size_t offset=0;offset<op.source.size();offset+=cap) connection.send(binary_detail::data,1,std::string_view(op.source).substr(offset,cap));
    connection.send(end,1);unsigned pings=0;
    auto receive=[&](){for(;;){auto frame=connection.receive(cap);
      if(frame.first.kind==ping){require(++pings<=4);connection.send(pong,0,frame.second);continue;}
      if(frame.first.kind==error || frame.first.kind==goaway) transport();
      require(frame.first.stream==1);return frame;
    }};
    auto first=receive();require(first.first.kind==response);auto reply=response_metadata(first.second,2);
    operation_detail::correlate(reply,op.method,op.target,op.options,consume!=nullptr);
    if(reply.streaming){
      failure.state_->response=std::move(reply.value);
      std::string page;std::size_t total=0;bool terminal=false,started=false;
      for(;;){auto frame=receive();
        if(frame.first.kind==end){require(started && page.empty());break;}
        require(frame.first.kind==binary_detail::data && !terminal && frame.second.size()<=max_document_bytes-total);total+=frame.second.size();
        for(char c:frame.second){require(!terminal);page+=c;
          if(c=='\n'){auto parsed=operation_detail::page(operation_detail::json(page,control),failure.state_->after);
            control.check();(*consume)(page);failure.state_->after=std::move(parsed.after);terminal=parsed.terminal;started=true;control.check();page.clear();
          }
        }
      }
      control.check();return{std::move(*failure.state_->response),failure.state_->after};
    }
    reply.value.body.reserve(static_cast<std::size_t>(reply.length));
    for(;;){auto frame=receive();if(frame.first.kind==end){require(reply.value.body.size()==reply.length);break;}
      require(frame.first.kind==binary_detail::data && frame.second.size()<=reply.length-reply.value.body.size());reply.value.body+=frame.second;}
    operation_detail::semantics(reply,op.method,op.target,op.type,op.source,control);control.check();
    failure.state_->response=std::move(reply.value);
    if(failure.state_->response->status>=400) throw Error(ErrorKind::http,"yamora: binary operation rejected",failure.state_->response->status);
    return{std::move(*failure.state_->response),failure.state_->after};
  } catch(const BinaryUnsupportedPeerError &){throw;}
    catch(const Error &error){failure.failure(error.kind(),error.status(),dispatched&&mutation&&(error.kind()!=ErrorKind::http||error.status()==408||error.status()>=500));throw failure;}
    catch(const std::bad_alloc &){failure.failure(ErrorKind::allocation,0,dispatched&&mutation);throw failure;}
}
} // namespace yamora
