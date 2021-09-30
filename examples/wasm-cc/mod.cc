// NOLINT(namespace-envoy)
#include <string>
#include <string_view>
#include <unordered_map>
#include <iostream>
#include <fstream>

//#include "common/http/utility.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/rule_message.h"
#include "proxy_wasm_intrinsics.h"
//#include "extensions/common/wasm/ext/envoy_proxy_wasm_api.h"

#include "utils.h"

class ExampleRootContext : public RootContext {
public:
  explicit ExampleRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}

  bool onStart(size_t /* vm_configuration_size */) override;
  bool onConfigure(size_t /* configuration_size */) override;
  void onTick() override;

  /**
   * This static function will be called by modsecurity and internally invoke logCb filter's method
   */
  static void logCb(void* data, const void* ruleMessagev);

  // get config
  const std::string&   rules_inline() const { return rules_inline_; }

  std::shared_ptr<modsecurity::ModSecurity> modsec() const { return modsec_; }
  std::shared_ptr<modsecurity::RulesSet> modsec_rules() const { return modsec_rules_; }
  std::shared_ptr<modsecurity::Transaction> modsec_transaction() const {return modsec_transaction_; }

  std::string configuration() { return configuration_; };

private:
  // rules config data from root context configurations
  std::string rules_inline_;

  // share modsecurity obj
  std::shared_ptr<modsecurity::ModSecurity> modsec_;
  std::shared_ptr<modsecurity::RulesSet> modsec_rules_;
  std::shared_ptr<modsecurity::Transaction> modsec_transaction_;

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

void ExampleRootContext::onTick() {
}

bool ExampleRootContext::onStart(size_t /* vm_configuration_size */) {
  return true;
}

bool ExampleRootContext::onConfigure(size_t configuration_size) {

  /* get inline configurations */
  auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration, 0, configuration_size);
  configuration_ = configuration_data->toString();
  rules_inline_ = configuration_;

  /* modsecurity initializing */
  modsec_.reset(new modsecurity::ModSecurity());
  modsec_->setConnectorInformation("ModSecurity-envoy v3.0.4 (ModSecurity)");
  modsec_->setServerLogCb(ExampleRootContext::logCb,
                          modsecurity::RuleMessageLogProperty | modsecurity::IncludeFullHighlightLogProperty);

  modsec_rules_.reset(new modsecurity::RulesSet());
  if (!rules_inline().empty()) {
      int rulesLoaded = modsec_rules_->load(rules_inline().c_str());
      if (rulesLoaded == -1) {
      } else {
      };
  }
  modsec_transaction_.reset(new modsecurity::Transaction(modsec().get(), modsec_rules().get(), this));

  return true;
}

void ExampleContext::onCreate() {

  // modsecurity initializing
  ExampleRootContext* root = dynamic_cast<ExampleRootContext*>(this->root());
  rules_inline_ = root->configuration();
  modsec_ = root->modsec();
  modsec_rules_ = root->modsec_rules();
  modsec_transaction_ = root->modsec_transaction();
}

FilterHeadersStatus ExampleContext::onRequestHeaders(uint32_t /* headers */, bool end_of_stream) {
  if (status_.intervined || status_.request_processed) {
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
  for (auto& p : pairs) {
    modsec_transaction_->addRequestHeader(std::string(p.first), std::string(p.second));
  }
  modsec_transaction_->processRequestHeaders();

  if (end_of_stream) {
    status_.request_processed = true;
  }
  if (intervention()) {
    return FilterHeadersStatus::StopIteration;
  }
  return getRequestHeadersStatus();
}

FilterDataStatus ExampleContext::onRequestBody(size_t body_buffer_length,
                                               bool end_of_stream) {

  return getRequestStatus();

}

FilterHeadersStatus ExampleContext::onResponseHeaders(uint32_t /* headers */, bool end_of_stream) {
  return getResponseHeadersStatus();
}

FilterDataStatus ExampleContext::onResponseBody(size_t body_buffer_length,
                                                bool end_of_stream) {
    return getResponseStatus();
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

void ExampleContext::onDone() { }

void ExampleContext::onLog() { }

void ExampleContext::onDelete() { }

bool ExampleContext::intervention() {
    if (!status_.intervined && modsec_transaction_->m_it.disruptive) {
        // status_.intervined must be set to true before sendLocalReply to avoid reentrancy when encoding the reply
        status_.intervined = true;

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
        return FilterHeadersStatus::StopIteration;
    }
    if (status_.request_processed) {
        return FilterHeadersStatus::Continue;
    }
    // If disruptive, hold until status_.request_processed, otherwise let the data flow.
    return modsec_transaction_->m_it.disruptive ? FilterHeadersStatus::StopIteration : FilterHeadersStatus::Continue;
}

FilterHeadersStatus ExampleContext::getResponseHeadersStatus() {
  if (status_.intervined || status_.response_processed) {
      return FilterHeadersStatus::Continue;
  }
  // If disruptive, hold until status_.response_processed, otherwise let the data flow.
  return modsec_transaction_->m_it.disruptive ? FilterHeadersStatus::StopIteration : FilterHeadersStatus::Continue;
}

FilterDataStatus ExampleContext::getRequestStatus() {
  if (status_.intervined) {
      return FilterDataStatus::StopIterationNoBuffer;
  }
  if (status_.request_processed) {
      return FilterDataStatus::Continue;
  }
  // If disruptive, hold until status_.request_processed, otherwise let the data flow.
  return modsec_transaction_->m_it.disruptive ? FilterDataStatus::StopIterationAndBuffer : FilterDataStatus::Continue;
}

FilterDataStatus ExampleContext::getResponseStatus() {
  if (status_.intervined || status_.response_processed) {
      // If intervined, let encodeData return the localReply
      return FilterDataStatus::Continue;
  }
  // If disruptive, hold until status_.response_processed, otherwise let the data flow.
  return modsec_transaction_->m_it.disruptive ? FilterDataStatus::StopIterationAndBuffer : FilterDataStatus::Continue;
}

void ExampleRootContext::logCb(void *data, const void *rulemessage) {
    const modsecurity::RuleMessage* ruleMessage = reinterpret_cast<const modsecurity::RuleMessage*>(rulemessage);

    if (ruleMessage == nullptr) {
        return;
    }

    /*
    LOG_INFO("* {} action. {}",
                    // Note - since ModSecurity >= v3.0.3 disruptive actions do not invoke the callback
                    // see https://github.com/SpiderLabs/ModSecurity/commit/91daeee9f6a61b8eda07a3f77fc64bae7c6b7c36
                    ruleMessage->m_isDisruptive ? "Disruptive" : "Non-disruptive",
                    modsecurity::RuleMessage::log(ruleMessage));
    */
}
