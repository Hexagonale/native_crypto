#include "include/crypto/crypto_plugin.h"
#include "include/crypto/aes_cbc_cipher.h"

// This must be included before many other Windows headers.
#include <windows.h>

#include <Intsafe.h>

#include <flutter/basic_message_channel.h>
#include <flutter/binary_messenger.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <map>
#include <memory>
#include <sstream>

#pragma warning(disable : 4267)
#pragma warning(disable : 4018)
#pragma warning(disable : 4189)

using namespace flutter;

CryptoPlugin::CryptoPlugin() {}
CryptoPlugin::~CryptoPlugin() {
    delete this->buffer;
}

void CryptoPlugin::RegisterWithRegistrar(PluginRegistrarWindows* registrar) {
    std::unique_ptr<CryptoPlugin> plugin = std::make_unique<CryptoPlugin>();
    plugin.get()->init(registrar);

    registrar->AddPlugin(std::move(plugin));
}

void CryptoPlugin::init(PluginRegistrarWindows* registrar) {
    this->channel = new MethodChannel<EncodableValue>(registrar->messenger(), "crypto", &flutter::StandardMethodCodec::GetInstance());
    this->channel->SetMethodCallHandler([&](const auto& call, auto result) {
        this->HandleMethodCall(call, std::move(result));
    });

    this->binaryChannel = new BasicMessageChannel(registrar->messenger(), "data", this);
    this->binaryChannel->SetMessageHandler([&](const std::vector<uint8_t>& message, const MessageReply<std::vector<uint8_t>>& reply) {
        std::vector<uint8_t>* msg = (std::vector<uint8_t>*)&message;

        this->HandleBinaryMessage(msg, reply);
    });
}

// region Messages Handlers
void CryptoPlugin::HandleBinaryMessage(std::vector<uint8_t>* message, const MessageReply<std::vector<uint8_t>>& reply) {
    const int size = message->size();

    delete this->buffer;
    this->buffer = new std::vector<uint8_t>(size);

    for (int i = 1; i < size; i++) {
        (*this->buffer)[i] = (*message)[i];
    }

    reply(std::vector<uint8_t>());
}

void CryptoPlugin::HandleMethodCall(const flutter::MethodCall<flutter::EncodableValue>& method_call, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
    if (method_call.method_name().compare("create") == 0) {
        const flutter::EncodableMap* arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());

        std::vector<uint8_t> key = std::get<std::vector<uint8_t>>(arguments->find(flutter::EncodableValue("key"))->second);
        std::vector<uint8_t> iv = std::get<std::vector<uint8_t>>(arguments->find(flutter::EncodableValue("iv"))->second);
        bool forEncryption = std::get<bool>(arguments->find(flutter::EncodableValue("encryption"))->second);

        AesCbcCipher* cipher = new AesCbcCipher(key, iv.data(), forEncryption);
        if (!cipher->isReady()) {
            delete cipher;
            result->Error("1", "Cannot initialize cipher.");

            return;
        }

        this->ciphers.push_back(cipher);
        result->Success(flutter::EncodableValue((int)this->ciphers.size() - 1));

        return;
    }

    if (method_call.method_name().compare("process") == 0) {
        int id = *std::get_if<int>(method_call.arguments());

        AesCbcCipher* cipher = this->ciphers.at(id);
        if (!cipher->isReady()) {
            result->Error("1", "Cipher is not ready.");
            return;
        }

        if (this->buffer->size() == 0) {
            result->Error("2", "Buffer is empty.");
            return;
        }

        if (this->buffer->size() % BLOCK_SIZE != 0) {
            result->Error("3", "Buffer size is incorrect.");
            return;
        }

        cipher->process(this->buffer->data(), this->buffer->size());
        binaryChannel->Send(*this->buffer);
        result->Success(flutter::EncodableValue(true));

        return;
    }

    if (method_call.method_name().compare("close") == 0) {
        const int id = *std::get_if<int>(method_call.arguments());

        if (id >= this->ciphers.size()) {
            result->Error("1", "No such cipher.");
            return;
        }

        this->ciphers.erase(this->ciphers.begin() + id);
        result->Success(true);

        return;
    }

    result->NotImplemented();
}
// endregion

// region Message Decoder
std::unique_ptr<std::vector<uint8_t>> CryptoPlugin::DecodeMessageInternal(const uint8_t* binary_message, const size_t message_size) const {
    std::unique_ptr<std::vector<uint8_t>> vector = std::make_unique<std::vector<uint8_t>>(binary_message, binary_message + message_size);

    return vector;
}

std::unique_ptr<std::vector<uint8_t>> CryptoPlugin::EncodeMessageInternal(const std::vector<uint8_t>& message) const {
    std::unique_ptr<std::vector<uint8_t>> msg = std::make_unique<std::vector<uint8_t>>(message.size());

    for (int i = 0; i < message.size(); i++) {
        (*msg)[i] = message[i];
    }

    return msg;
}
// endregion

// region Registrar
void CryptoPluginRegisterWithRegistrar(FlutterDesktopPluginRegistrarRef registrar) {
    CryptoPlugin::RegisterWithRegistrar(flutter::PluginRegistrarManager::GetInstance()->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
// endregion