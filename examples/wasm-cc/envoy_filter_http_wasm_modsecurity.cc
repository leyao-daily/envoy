// NOLINT(namespace-envoy)
#include <string>
#include <string_view>
#include <unordered_map>

//#include "common/http/utility.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "proxy_wasm_intrinsics.h"
//#include "extensions/common/wasm/ext/envoy_proxy_wasm_api.h"

#include "utils.h"

class ExampleRootContext : public RootContext {
public:
  explicit ExampleRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}

  bool onStart(size_t /* vm_configuration_size */) override;
  bool onConfigure(size_t /* configuration_size */) override;
  void onTick() override;

  std::string configuration() { return configuration_; };

private:
  std::string configuration_;
};

class ExampleContext : public Context {
public:
  explicit ExampleContext(uint32_t id, RootContext* root) : Context(id, root) {}

  void onCreate() override;

  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onRequestBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterMetadataStatus onRequestMetadata(uint32_t) override;
  FilterTrailersStatus onRequestTrailers(uint32_t) override;

  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onResponseBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterMetadataStatus onResponseMetadata(uint32_t) override;
  FilterTrailersStatus onResponseTrailers(uint32_t) override;

  void onDone() override;
  void onLog() override;
  void onDelete() override;

  // get config
  const std::string& rules_inline() const { return rules_inline_; }

  std::shared_ptr<modsecurity::ModSecurity> modsec() const { return modsec_; }
  std::shared_ptr<modsecurity::RulesSet> modsec_rules() const { return modsec_rules_; }

private:
  // rules config data from root context configurations
  std::string rules_inline_;

  // share modsecurity obj
  std::shared_ptr<modsecurity::ModSecurity> modsec_;
  std::shared_ptr<modsecurity::RulesSet> modsec_rules_;
  std::shared_ptr<modsecurity::Transaction> modsec_transaction_;

  FilterHeadersStatus getRequestHeadersStatus();
  FilterHeadersStatus getResponseHeadersStatus();
  FilterDataStatus getRequestStatus();
  FilterDataStatus getResponseStatus();

  /**
   * @return true if intervention of current transaction is disruptive, false otherwise
   */
  bool intervention();

  struct ModSecurityStatus {
    ModSecurityStatus() : intervined(0), request_processed(0), response_processed(0) {}
    bool intervined;
    bool request_processed;
    bool response_processed;
  };

  ModSecurityStatus status_;
};

static RegisterContextFactory register_ExampleContext(CONTEXT_FACTORY(ExampleContext),
                                                      ROOT_FACTORY(ExampleRootContext),
                                                      "my_root_id");

void ExampleRootContext::onTick() { LOG_TRACE("onTick"); }

bool ExampleRootContext::onStart(size_t vm_configuration_size) {
  LOG_TRACE("onStart");
  auto vm_configuration_data = getBufferBytes(WasmBufferType::VmConfiguration, 0, vm_configuration_size);
  std::string vm_configuration = vm_configuration_data->toString();
  LOG_INFO(std::string("vm configurations: ") + vm_configuration);
  return true;
}

bool ExampleRootContext::onConfigure(size_t configuration_size) {
  LOG_WARN("onConfigure");
  proxy_set_tick_period_milliseconds(1000); // 1 sec
  auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration, 0, configuration_size);
  configuration_ = configuration_data->toString();
  return true;
}

void ExampleContext::onCreate() {
  LOG_WARN(std::string("onCreate " + std::to_string(id())));

  // modsecurity initializing
  ExampleRootContext* root = dynamic_cast<ExampleRootContext*>(this->root());
  rules_inline_ = root->configuration();
  LOG_INFO(std::string("onCreate load configurations: ") + rules_inline_);
  modsec_.reset(new modsecurity::ModSecurity());
  modsec_->setConnectorInformation("ModSecurity-envoy v3.0.4 (ModSecurity)");
  modsec_rules_.reset(new modsecurity::RulesSet());
  if (!rules_inline().empty()) {
      int rulesLoaded = modsec_rules_->load(rules_inline().c_str());
      LOG_INFO("Loading ModSecurity inline rules");
      if (rulesLoaded == -1) {
          LOG_ERROR(std::string("Failed to load rules"));
      } else {
          LOG_INFO(std::string("Loaded inline rules: ") + std::to_string(rulesLoaded));
      };
  }
  modsec_transaction_.reset(new modsecurity::Transaction(modsec().get(), modsec_rules().get(), this));
}

FilterHeadersStatus ExampleContext::onRequestHeaders(uint32_t /* headers */, bool end_of_stream) {
  LOG_INFO(std::string("onRequestHeaders ") + std::to_string(id()));
  if (status_.intervined || status_.request_processed) {
    LOG_INFO("Processed");
    return getRequestHeadersStatus();
  }

  // modsecurity processConnection
  std::string remote_addr;
  int remote_port;
  std::string local_addr;
  int local_port;
  getValue({"source", "address"}, &remote_addr);
  getValue({"source", "port"}, &remote_port);
  getValue({"destination", "address"}, &local_addr);
  getValue({"destination", "port"}, &local_port);
  LOG_INFO(std::string("source address: ") + remote_addr + std::string(", dest address: ") + local_addr);
  modsec_transaction_->processConnection(split(remote_addr, ":")[0].c_str(), remote_port,
                                         split(local_addr, ":")[0].c_str(), local_port);
  if (intervention()) {
    return FilterHeadersStatus::StopIteration;
  }

  // modsecurity processURI
  std::string path = getRequestHeader(":path")->toString();
  std::string method = getRequestHeader(":method")->toString();
  std::string protocol;
  getValue({"request", "protocol"}, &protocol);
  modsec_transaction_->processURI(path.c_str(), method.c_str(), protocol.c_str());
  if (intervention()) {
    return FilterHeadersStatus::StopIteration;
  }

  // modsecurity processRequestHeaders
  auto result = getRequestHeaderPairs();
  auto pairs = result->pairs();
  LOG_INFO(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_INFO(std::string(p.first) + std::string(" -> ") + std::string(p.second));
    modsec_transaction_->addRequestHeader(std::string(p.first), std::string(p.second));
  }
  modsec_transaction_->processRequestHeaders();
  LOG_INFO(std::string("modsecurity process request header"));
  if (end_of_stream) {
    LOG_INFO(std::string("request processed"));
    status_.request_processed = true;
  }
  if (intervention()) {
    LOG_INFO(std::string("stop iteration"));
    return FilterHeadersStatus::StopIteration;
  }
  LOG_INFO(std::string("continue"));
  return FilterHeadersStatus::Continue;
}

FilterHeadersStatus ExampleContext::onResponseHeaders(uint32_t /* headers */, bool end_of_stream) {
  if (status_.intervined || status_.response_processed) {
    return getResponseHeadersStatus();
  }

  auto headers = getResponseHeaderPairs();
  auto pairs = headers->pairs();
  for (auto& p : pairs) {
    LOG_INFO(std::string(p.first) + std::string(" -> ") + std::string(p.second));
    modsec_transaction_->addResponseHeader(std::string(p.first), std::string(p.second));
  }
  int response_code;
  std::string protocol;
  getValue({"response", "code"}, &response_code);
  getValue({"request", "protocol"}, &protocol);
  // TODO(luyao): get response protocol
  LOG_INFO("modsecurity processResponseHeaders start");
  modsec_transaction_->processResponseHeaders(response_code, protocol.c_str());
  LOG_INFO("modsecurity processResponseHeaders done");

  if (end_of_stream) {
    LOG_INFO(std::string("response processed"));
    status_.response_processed = true;
  }
  if (intervention()) {
      LOG_INFO(std::string("stop iteration"));
      return FilterHeadersStatus::StopIteration;
  }
  LOG_INFO(std::string("getResponseHeadersStatus"));
  return getResponseHeadersStatus();
}

FilterDataStatus ExampleContext::onRequestBody(size_t body_buffer_length,
                                               bool end_of_stream) {

  LOG_INFO("ModSecurityFilter::decodeData");
  if (status_.intervined || status_.request_processed) {
      LOG_INFO("Processed");
      return getRequestStatus();
  }
  auto body = getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);
  LOG_INFO(std::string(body->view()));
  /*
  for (const Buffer::RawSlice& slice : data.getRawSlices()) {
      size_t requestLen = modsec_transaction_->getRequestBodyLength();
      // If append fails or append reached the limit, test for intervention (in case SecRequestBodyLimitAction is set to Reject)
      // Note, we can't rely solely on the return value of append, when SecRequestBodyLimitAction is set to Reject it returns true and sets the intervention
      if (modsec_transaction_->appendRequestBody(static_cast<unsigned char*>(slice.mem_), slice.len_) == false ||
          (slice.len_ > 0 && requestLen == modsec_transaction_->getRequestBodyLength())) {
          ENVOY_LOG(info, "ModSecurityFilter::decodeData appendRequestBody reached limit");
          if (intervention()) {
              return Http::FilterDataStatus::StopIterationNoBuffer;
          }
          // Otherwise set to process request
          end_of_stream = true;
          break;
      }
  }
 */
  if (end_of_stream) {
      LOG_INFO(std::string("request processed"));
      status_.request_processed = true;
      modsec_transaction_->processRequestBody();
  }
  if (intervention()) {
      return FilterDataStatus::StopIterationNoBuffer;
  }
  return getRequestStatus();

}

FilterDataStatus ExampleContext::onResponseBody(size_t body_buffer_length,
                                                bool /* end_of_stream */) {
  auto body = getBufferBytes(WasmBufferType::HttpResponseBody, 0, body_buffer_length);
  //setBuffer(WasmBufferType::HttpResponseBody, 0, 12, "Hello, world");
  LOG_INFO(std::string("onReponseBody ") + std::string(body->view()));
  return FilterDataStatus::Continue;
}

FilterMetadataStatus ExampleContext::onRequestMetadata(uint32_t) {
  return FilterMetadataStatus::Continue;
}

FilterMetadataStatus ExampleContext::onResponseMetadata(uint32_t) {
  return FilterMetadataStatus::Continue;
}

FilterTrailersStatus ExampleContext::onRequestTrailers(uint32_t) {
  return FilterTrailersStatus::Continue;
}

FilterTrailersStatus ExampleContext::onResponseTrailers(uint32_t) {
  return FilterTrailersStatus::Continue;
}

void ExampleContext::onDone() { LOG_WARN(std::string("onDone " + std::to_string(id()))); }

void ExampleContext::onLog() { LOG_WARN(std::string("onLog " + std::to_string(id()))); }

void ExampleContext::onDelete() { LOG_WARN(std::string("onDelete " + std::to_string(id()))); }

bool ExampleContext::intervention() {
    if (!status_.intervined && modsec_transaction_->m_it.disruptive) {
        // status_.intervined must be set to true before sendLocalReply to avoid reentrancy when encoding the reply
        status_.intervined = true;
        LOG_INFO("intervention");
        /*
        inline WasmResult sendLocalResponse(uint32_t response_code, std::string_view response_code_details,
                                    std::string_view body,
                                    const HeaderStringPairs &additional_response_headers,
                                    GrpcStatus grpc_status = GrpcStatus::InvalidCode) {
        */
        std::vector<std::pair<std::string, std::string>> pairs;
        if (modsec_transaction_->m_it.status == 302) {
          pairs.push_back(std::make_pair(std::string("location"), std::string(modsec_transaction_->m_it.url)));
        }
        sendLocalResponse(modsec_transaction_->m_it.status, "", "", pairs);
    }
    return status_.intervined;
}

FilterHeadersStatus ExampleContext::getRequestHeadersStatus() {
    if (status_.intervined) {
        LOG_INFO("StopIteration");
        return FilterHeadersStatus::StopIteration;
    }
    if (status_.request_processed) {
        LOG_INFO("Continue");
        return FilterHeadersStatus::Continue;
    }
    // If disruptive, hold until status_.request_processed, otherwise let the data flow.
    LOG_INFO("RuleEngine");
    return modsec_transaction_->getRuleEngineState() == modsecurity::RulesSetProperties::EnabledRuleEngine ?
                FilterHeadersStatus::StopIteration : FilterHeadersStatus::Continue;
}

FilterHeadersStatus ExampleContext::getResponseHeadersStatus() {
  if (status_.intervined || status_.response_processed) {
      LOG_INFO("Continue");
      return FilterHeadersStatus::Continue;
  }
  // If disruptive, hold until status_.response_processed, otherwise let the data flow.
  LOG_INFO("RuleEngine");
  return modsec_transaction_->getRuleEngineState() == modsecurity::RulesSetProperties::EnabledRuleEngine ?
              FilterHeadersStatus::StopIteration : FilterHeadersStatus::Continue;
}

FilterDataStatus ExampleContext::getRequestStatus() {
  if (status_.intervined) {
      LOG_INFO("StopIterationNoBuffer");
      return FilterDataStatus::StopIterationNoBuffer;
  }
  if (status_.request_processed) {
      LOG_INFO("Continue");
      return FilterDataStatus::Continue;
  }
  // If disruptive, hold until status_.request_processed, otherwise let the data flow.
  LOG_INFO("RuleEngine");
  return modsec_transaction_->getRuleEngineState() == modsecurity::RulesSetProperties::EnabledRuleEngine ?
              FilterDataStatus::StopIterationAndBuffer :
              FilterDataStatus::Continue;
}

FilterDataStatus ExampleContext::getResponseStatus() {
  if (status_.intervined || status_.response_processed) {
      // If intervined, let encodeData return the localReply
      LOG_INFO("Continue");
      return FilterDataStatus::Continue;
  }
  // If disruptive, hold until status_.response_processed, otherwise let the data flow.
  LOG_INFO("RuleEngine");
  return modsec_transaction_->getRuleEngineState() == modsecurity::RulesSetProperties::EnabledRuleEngine ?
              FilterDataStatus::StopIterationAndBuffer :
              FilterDataStatus::Continue;
}
