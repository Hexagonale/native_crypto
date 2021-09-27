#ifndef FLUTTER_PLUGIN_CRYPTO_PLUGIN_H_
#define FLUTTER_PLUGIN_CRYPTO_PLUGIN_H_

#include <map>
#include <memory>
#include <sstream>

#include <flutter/basic_message_channel.h>
#include <flutter/binary_messenger.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <flutter_plugin_registrar.h>

#include "aes_cbc_cipher.h"

#ifdef FLUTTER_PLUGIN_IMPL
#define FLUTTER_PLUGIN_EXPORT __declspec(dllexport)
#else
#define FLUTTER_PLUGIN_EXPORT __declspec(dllimport)
#endif

#if defined(__cplusplus)
extern "C" {
#endif

FLUTTER_PLUGIN_EXPORT void CryptoPluginRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar);

#if defined(__cplusplus)
}  // extern "C"
#endif

using namespace flutter;

class CryptoPlugin : public Plugin, MessageCodec<std::vector<uint8_t>> {
   public:
    static void RegisterWithRegistrar(PluginRegistrarWindows* registrar);
    void init(PluginRegistrarWindows* registrar);

    CryptoPlugin();
    ~CryptoPlugin();

   private:
    MethodChannel<EncodableValue>* channel;
    BasicMessageChannel<std::vector<uint8_t>>* binaryChannel;

    std::vector<AesCbcCipher*> ciphers;
    std::vector<uint8_t>* buffer = new std::vector<uint8_t>();

    void HandleMethodCall(const MethodCall<EncodableValue>& method_call, std::unique_ptr<MethodResult<EncodableValue>> result);
    void HandleBinaryMessage(std::vector<uint8_t>* message, const MessageReply<std::vector<uint8_t>>& reply);

    std::unique_ptr<std::vector<uint8_t>> DecodeMessageInternal(const uint8_t* binary_message, const size_t message_size) const;
    std::unique_ptr<std::vector<uint8_t>> EncodeMessageInternal(const std::vector<uint8_t>& message) const;
};

#endif  // FLUTTER_PLUGIN_CRYPTO_PLUGIN_H_
