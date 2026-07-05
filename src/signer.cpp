#include "ethyl/signer.hpp"

#include "ecdsa_util.h"
#include "ethyl/transaction.hpp"
#include "ethyl/utils.hpp"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <array>
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace ethyl {

Signer::Signer() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char randomize[32] = {};

    if (!ethyl_fill_random(randomize, sizeof(randomize))) {
        ethyl_secure_erase(randomize, sizeof(randomize));
        throw std::runtime_error("Failed to generate randomness");
    }

    if (!secp256k1_context_randomize(ctx, randomize)) {
        ethyl_secure_erase(randomize, sizeof(randomize));
        throw std::runtime_error("Failed to randomize context");
    }

    // Security improvement:
    // Clear context-randomization entropy after libsecp256k1 consumes it.
    // This avoids leaving unnecessary random material in stack memory.
    ethyl_secure_erase(randomize, sizeof(randomize));
}

Signer::~Signer() {
    secp256k1_context_destroy(ctx);
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> Signer::generate_key_pair() {
    unsigned char seckey[32] = {};
    unsigned char compressed_pubkey[33] = {};
    size_t len = 0;
    secp256k1_pubkey pubkey = {};

    while (true) {
        if (!ethyl_fill_random(seckey, sizeof(seckey))) {
            ethyl_secure_erase(seckey, sizeof(seckey));
            throw std::runtime_error("Failed to generate randomness");
        }

        if (secp256k1_ec_seckey_verify(ctx, seckey))
            break;
    }

    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) {
        ethyl_secure_erase(seckey, sizeof(seckey));
        throw std::runtime_error("Failed to create pubkey");
    }

    len = sizeof(compressed_pubkey);

    if (!secp256k1_ec_pubkey_serialize(
            ctx,
            compressed_pubkey,
            &len,
            &pubkey,
            SECP256K1_EC_COMPRESSED)) {
        ethyl_secure_erase(seckey, sizeof(seckey));
        throw std::runtime_error("Failed to serialize pubkey");
    }

    assert(len == sizeof(compressed_pubkey));

    // Keep existing behavior: returns {seckey, pubkey}.
    // NOTE: This conflicts with signer.hpp comment: "Returns <Pubkey, Seckey>".
    // Left unchanged to avoid breaking existing callers.
    std::vector<unsigned char> secret(
            seckey,
            seckey + sizeof(seckey));

    std::vector<unsigned char> pub(
            compressed_pubkey,
            compressed_pubkey + sizeof(compressed_pubkey));

    // Security improvement:
    // Clear the temporary stack copy of the private key after it has been copied
    // into the returned vector. The returned vector intentionally keeps the key;
    // this removes only the unnecessary leftover copy.
    ethyl_secure_erase(seckey, sizeof(seckey));

    return {std::move(secret), std::move(pub)};
}

Bytes20 Signer::secretKeyToAddress(std::span<const unsigned char> seckey) {
    if (!secp256k1_ec_seckey_verify(ctx, seckey.data()))
        throw std::runtime_error("Failed to verify secret key");

    secp256k1_pubkey pubkey = {};

    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey.data()))
        throw std::runtime_error("Failed to create public key");

    std::array<unsigned char, 65> pub = {};
    size_t pub_len = pub.max_size();

    secp256k1_ec_pubkey_serialize(
            ctx,
            pub.data(),
            &pub_len,
            &pubkey,
            SECP256K1_EC_UNCOMPRESSED);

    std::string_view pub_string(
            reinterpret_cast<const char*>(pub.data()) + 1,
            pub.size() - 1);

    Bytes32 hashed_pub = utils::hashBytes(pub_string);

    Bytes20 result = {};
    std::memcpy(
            result.data(),
            hashed_pub.data() + hashed_pub.size() - result.size(),
            result.size());

    return result;
}

std::string Signer::secretKeyToAddressString(std::span<const unsigned char> seckey) {
    Bytes20 address = secretKeyToAddress(seckey);
    return "0x" + oxenc::to_hex(address.begin(), address.end());
}

void Signer::populateTransaction(Transaction& tx, std::string senderAddress) {
    if (!provider->numClients()) {
        throw std::runtime_error(
                "Signer does not have a provider with any RPC backends set. "
                "Ensure that the provider has atleast one client");
    }

    if (tx.nonce == 0)
        tx.nonce = provider->getTransactionCount(senderAddress, "pending");

    const uint64_t networkChainId = provider->getChainId();

    if (tx.chainId != 0) {
        if (tx.chainId != networkChainId)
            throw std::runtime_error("Chain ID on transaction does not match providers Chain ID");
    } else {
        tx.chainId = networkChainId;
    }

    const auto feeData = provider->getFeeData();

    if (tx.maxFeePerGas == 0)
        tx.maxFeePerGas = feeData.maxFeePerGas;

    if (tx.maxPriorityFeePerGas == 0)
        tx.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas;
}

std::vector<unsigned char> sign_old(
        secp256k1_context* ctx,
        const std::array<unsigned char, 32>& hash,
        std::span<const unsigned char> seckey) {
    secp256k1_ecdsa_recoverable_signature sig = {};
    unsigned char serialized_signature[64] = {};
    int recid = 0;

    if (!secp256k1_ecdsa_sign_recoverable(
            ctx,
            &sig,
            hash.data(),
            seckey.data(),
            nullptr,
            nullptr)) {
        ethyl_secure_erase(&sig, sizeof(sig));
        ethyl_secure_erase(serialized_signature, sizeof(serialized_signature));
        throw std::runtime_error("Failed to sign");
    }

    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(
            ctx,
            serialized_signature,
            &recid,
            &sig)) {
        ethyl_secure_erase(&sig, sizeof(sig));
        ethyl_secure_erase(serialized_signature, sizeof(serialized_signature));
        throw std::runtime_error("Failed to serialize signature");
    }

    std::vector<unsigned char> signature(
            serialized_signature,
            serialized_signature + sizeof(serialized_signature));

    signature.push_back(static_cast<unsigned char>(recid));

    // Security improvement:
    // Clear temporary signing artifacts after they have been copied into the
    // returned vector. The returned compact signature remains intact.
    ethyl_secure_erase(&sig, sizeof(sig));
    ethyl_secure_erase(serialized_signature, sizeof(serialized_signature));

    return signature;
}

ECDSACompactSignature Signer::sign32(
        std::span<const unsigned char, 32> hash,
        std::span<const unsigned char> seckey) {
    secp256k1_ecdsa_recoverable_signature sig = {};
    ECDSACompactSignature result = {};
    int recoveryID = 0;

    if (!secp256k1_ecdsa_sign_recoverable(
            ctx,
            &sig,
            hash.data(),
            seckey.data(),
            nullptr,
            nullptr)) {
        ethyl_secure_erase(&sig, sizeof(sig));
        throw std::runtime_error("Failed to sign");
    }

    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(
            ctx,
            result.data(),
            &recoveryID,
            &sig)) {
        ethyl_secure_erase(&sig, sizeof(sig));
        ethyl_secure_erase(result.data(), result.size());
        throw std::runtime_error("Failed to serialize signature");
    }

    // Security improvement:
    // Clear the temporary secp256k1 signature object after serialization.
    // The returned compact signature remains intact; this only removes
    // intermediate signing state from stack memory.
    ethyl_secure_erase(&sig, sizeof(sig));

    assert(recoveryID <= 255);
    result.back() = static_cast<unsigned char>(recoveryID);

    return result;
}

ECDSACompactSignature Signer::signMessage(
        std::string_view message,
        std::span<const unsigned char> seckey) {
    Bytes32 hash = utils::hashBytes(message);
    return sign32(hash, seckey);
}

std::vector<unsigned char> Signer::signTransaction(
        Transaction& tx,
        std::span<const unsigned char> seckey) {
    ECDSACompactSignature signature = sign32(tx.hash(), seckey);
    tx.sig.set(signature);
    return tx.serialize();
}

std::string Signer::signTransactionAsHex(
        Transaction& tx,
        std::span<const unsigned char> seckey) {
    std::vector<unsigned char> signature = signTransaction(tx, seckey);
    return oxenc::to_hex(signature.begin(), signature.end());
}

std::string Signer::sendTransaction(
        Transaction& tx,
        std::span<const unsigned char> seckey) {
    const auto senders_address = secretKeyToAddressString(seckey);
    populateTransaction(tx, senders_address);
    signTransaction(tx, seckey);
    return provider->sendTransaction(tx);
}

} // namespace ethyl