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

		auto kl = wc::get_size_property(key.get(), BCRYPT_KEY_LENGTH);
		Logger::WriteMessage(algorithm);
		Logger::WriteMessage(L":");
		Logger::WriteMessage(std::to_wstring(kl).c_str());

		auto cipher = wc::encrypt(key, std::vector<byte>(&plain[0], &plain[0] + plain.size()), iv);
		auto decrypted = wc::decrypt(key, cipher, iv);
		auto decryptedText = std::string(decrypted.begin(), decrypted.end());

		Assert::AreEqual(decryptedText, plain);
	}
};