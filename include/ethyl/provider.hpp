// Provider.hpp
#pragma once

#include <forward_list>
#include <functional>
#include <string>
#include <string_view>
#include <optional>
#include <variant>
#include <queue>
#include <chrono>
#include <mutex>

#include <nlohmann/json_fwd.hpp>

#include "transaction.hpp"
#include "logs.hpp"

using namespace std::literals;

namespace cpr {
class Session;
}

namespace ethyl
{

struct FeeData {
    uint64_t gasPrice;
    uint64_t maxFeePerGas;
    uint64_t maxPriorityFeePerGas;

    FeeData(uint64_t _gasPrice, uint64_t _maxFeePerGas, uint64_t _maxPriorityFeePerGas)
        : gasPrice(_gasPrice), maxFeePerGas(_maxFeePerGas), maxPriorityFeePerGas(_maxPriorityFeePerGas) {}
};

struct Client {
    std::string name;
    std::string url;
};

struct InfoBase {
    size_t index;
    bool success{false};
};
struct HeightInfo : InfoBase {
    uint64_t height{0};
};
struct ChainIdInfo : InfoBase {
    uint64_t chainId{0};
};

struct Provider : public std::enable_shared_from_this<Provider> {

protected:
    Provider();
public:

    static std::shared_ptr<Provider> make_provider() {
        return std::shared_ptr<Provider>{new Provider{}};
    }

    template <typename Ret>
    using optional_callback = std::function<void(std::optional<Ret>)>;

    using json_result_callback = optional_callback<nlohmann::json>;

    /// An error response to a JSON-RPC request (as opposed to a failure to get a response at all).
    struct JsonRpcError {
        int64_t code = 0;
        std::string message;

        /// True if this is the error of an eth_call whose execution reverted (as calling a
        /// function that the contract doesn't have does).
        bool is_execution_reverted() const;
    };

    /// The outcome of a JSON-RPC request: its result, an error response, or (monostate) no usable
    /// response at all, such as after a connection failure or timeout.
    using json_response = std::variant<std::monostate, nlohmann::json, JsonRpcError>;
    using json_response_callback = std::function<void(json_response)>;

    /** Add a RPC backend for interacting with the Ethereum network.
     *
     * The provider does not ensure that no duplicates are added to the list.
     *
     * @param name A label for the type of client being added. This information
     * is stored only for the user to identify the client in the list of
     * clients in a given provider.
     *
     * @returns True if the client was added successfully. False if the `url`
     * was not set.
     */
    void addClient(std::string name, std::string url);

    // Updates the request timeout used for new requests
    void setTimeout(std::chrono::milliseconds timeout);

    // The default timeout applied (if setTimeout is not called)
    static constexpr auto DEFAULT_TIMEOUT = 3s;

    bool connectToNetwork();
    void disconnectFromNetwork();

    uint64_t getTransactionCount(std::string_view address, std::string_view blockTag);
    void getTransactionCountAsync(std::string_view address, std::string_view blockTag, optional_callback<uint64_t> user_cb);
    nlohmann::json callReadFunctionJSON(std::string_view address, std::string_view data, std::string_view blockNumber = "latest");
    void callReadFunctionJSONAsync(std::string_view address, std::string_view data, json_result_callback user_cb, std::string_view blockNumber = "latest");
    /// Like callReadFunctionJSONAsync, but reports an error response (such as an execution revert)
    /// separately from a failure to get any response.  Unlike the other requests, an error response
    /// is not retried with the next client: it is the answer.
    void callReadFunctionAsync(std::string_view address, std::string_view data, json_response_callback user_cb, std::string_view blockNumber = "latest");
    std::string callReadFunction(std::string_view address, std::string_view data, std::string_view blockNumber = "latest");
    std::string callReadFunction(std::string_view address, std::string_view data, uint64_t blockNumber);

    uint64_t getChainId();
    void getChainIdAsync(optional_callback<uint64_t> user_cb);
    std::string evm_snapshot();
    void evm_snapshot_async(json_result_callback cb);
    bool evm_revert(std::string_view snapshotId);

    // Enables or disables, based on the single boolean argument, the automatic
    // mining of new blocks with each new transaction submitted to the network.
    // You can use hardhat_getAutomine to get the current value.
    bool evm_setAutomine(bool enable);

    // Force a block to be mined. Takes no parameters. Mines a block independent
    // of whether or not mining is started or stopped.
    bool evm_mine();
    uint64_t evm_increaseTime(std::chrono::seconds seconds);

    std::optional<nlohmann::json> getTransactionByHash(std::string_view transactionHash);
    void getTransactionByHashAsync(std::string_view transactionHash, json_result_callback cb);
    std::optional<nlohmann::json> getTransactionReceipt(std::string_view transactionHash);
    void getTransactionReceiptAsync(std::string_view transactionHash, json_result_callback cb);
    std::vector<LogEntry> getLogs(uint64_t fromBlock, uint64_t toBlock, std::string_view address);
    std::vector<LogEntry> getLogs(uint64_t block, std::string_view address);
    void getLogsAsync(uint64_t fromBlock, uint64_t toBlock, std::string_view address, optional_callback<std::vector<LogEntry>> user_cb);
    void getLogsAsync(uint64_t block, std::string_view address, optional_callback<std::vector<LogEntry>> cb);
    std::string getContractStorageRoot(std::string_view address, uint64_t blockNumberInt);
    std::string getContractStorageRoot(std::string_view address, std::string_view blockNumber = "latest");
    void getContractStorageRootAsync(std::string_view address, optional_callback<std::string> user_cb, uint64_t blockNumberInt);
    void getContractStorageRootAsync(std::string_view address, optional_callback<std::string> user_cb, std::string_view blockNumber = "latest");

    std::string sendTransaction(const Transaction& signedTx);
    std::string sendUncheckedTransaction(const Transaction& signedTx);
    void sendUncheckedTransactionAsync(const Transaction& signedTx, optional_callback<std::string> user_cb);

    uint64_t waitForTransaction(std::string_view txHash, std::chrono::milliseconds timeout = 320s);
    bool transactionSuccessful(std::string_view txHash, std::chrono::milliseconds timeout = 320s);
    uint64_t gasUsed(std::string_view txHash, std::chrono::milliseconds timeout = 320s);
    std::string getBalance(std::string_view address);
    void getBalanceAsync(std::string_view address, optional_callback<std::string> user_cb);
    std::string getContractDeployedInLatestBlock();

    uint64_t getLatestHeight();
    void getLatestHeightAsync(optional_callback<uint64_t> user_cb);
    FeeData getFeeData();

    size_t numClients();

    std::vector<Client> getClients();

    std::vector<size_t> getClientOrder();
    void setClientOrder(std::vector<size_t> order);

    void makeJsonRpcRequest(std::string_view method,
                                     const nlohmann::json& params,
                                     json_result_callback cb,
                                     std::forward_list<size_t> client_indices = {},
                                     bool should_try_next = true);
    /// Like makeJsonRpcRequest, but reports the full outcome.  If `retry_error_response` is false
    /// then an error response is reported rather than retried with the next client.
    void makeJsonRpcRequestResponse(std::string_view method,
                                     const nlohmann::json& params,
                                     json_response_callback cb,
                                     std::forward_list<size_t> client_indices = {},
                                     bool should_try_next = true,
                                     bool retry_error_response = true);
    std::optional<nlohmann::json> makeJsonRpcRequest(std::string_view method,
                                     const nlohmann::json& params,
                                     std::forward_list<size_t> client_indices = {},
                                     bool should_try_next = true);

    std::vector<HeightInfo> getAllHeights();
    void getAllHeightsAsync(std::function<void(std::vector<HeightInfo>)> user_cb);

    std::vector<ChainIdInfo> getAllChainIds();
    void getAllChainIdsAsync(std::function<void(std::vector<ChainIdInfo>)> user_cb);

private:

    /// List of clients for interacting with the Ethereum network via RPC
    /// The order of the clients dictates the order in which a request is
    /// attempted.
    std::vector<Client> clients;

    /// Allows the user to specify a different order in which to try provider clients
    /// if the user finds that one or more clients is performing badly.  This is
    /// separate from `clients` so that the order in `clients` remains stable.
    std::vector<size_t> client_order;

    std::map<std::string, std::queue<std::shared_ptr<cpr::Session>>> client_sessions;

    // Gets or creates a cpr Session for the given URL (if it is added in clients)
    // This function DOES NOT lock the mutex; it assumes the caller already has!
    std::shared_ptr<cpr::Session> get_client_session(const std::string& url);

    std::chrono::milliseconds request_timeout{DEFAULT_TIMEOUT};

    std::mutex mutex;
};
} // namespace ethyl
