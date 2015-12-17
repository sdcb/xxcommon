#include <CppUnitTest.h>
#include <winbcrypt\winbcrypt.h>
#include <text_util\text_util.h>
#include <array>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std::string_literals;
namespace wc = winbcrypt;
namespace tu = text_util;

TEST_CLASS(Winbcrypt_Symmetric)
{
	TEST_METHOD(Aes256)
	{
		process(BCRYPT_AES_ALGORITHM, 256);
	}

	TEST_METHOD(Aes128)
	{
		process(BCRYPT_AES_ALGORITHM, 128);
	}

	TEST_METHOD(Des)
	{
		process(BCRYPT_DES_ALGORITHM, 64);
	}

	TEST_METHOD(Des3)
	{
		process(BCRYPT_3DES_ALGORITHM, 192);
	}

	void process(wchar_t const * algorithm, size_t keybits)
	{
		auto p = wc::open_provider(algorithm);
		auto keyBuffer = wc::create_pbkdf2_key(tu::to_buffer("Hello World"s), keybits / 8);
		auto key = wc::create_key(p, keyBuffer);
		
		auto ivSize = wc::get_size_property(p.get(), BCRYPT_BLOCK_LENGTH);
		auto iv = wc::random_blob(ivSize);

		auto plain = "Hello World"s;
		auto cipher = wc::encrypt(key, tu::to_buffer(plain), iv);
		auto decrypted = wc::decrypt(key, cipher, iv);
		auto decryptedText = std::string(decrypted.begin(), decrypted.end());

		Assert::AreEqual(decryptedText, plain);
	}

	TEST_METHOD(Aes256_Decrypt)
	{
		const auto iv64 = "W7CLuikA6srjcQ0dc3GyBQ=="s;
		const auto key64 = "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4="s;
		const auto encrypted64 = "ggoCaTSejdi0IU4X02GpzA=="s;

		auto iv = tu::decode64(iv64);
		auto keys = tu::decode64(key64);
		auto encrypted = tu::decode64(encrypted64);

		auto p = wc::open_provider(BCRYPT_AES_ALGORITHM);
		auto key = wc::create_key(p, keys);
		
		auto decrypted = wc::decrypt(key, encrypted, iv);
		auto decryptedText = std::string(decrypted.begin(), decrypted.end());

		Assert::AreEqual(decryptedText, "Hello World"s);
	}
};