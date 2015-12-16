#include <CppUnitTest.h>
#include <winbcrypt\winbcrypt.h>
#include <text64\text64.h>
#include <array>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std::string_literals;
namespace wc = winbcrypt;

TEST_CLASS(Winbcrypt_Symmetric)
{
	TEST_METHOD(Aes256)
	{
		process(BCRYPT_AES_ALGORITHM, BCRYPT_SHA256_ALGORITHM);
	}

	TEST_METHOD(Aes128)
	{
		process(BCRYPT_AES_ALGORITHM, BCRYPT_MD5_ALGORITHM);
	}

	TEST_METHOD(Des)
	{
		process(BCRYPT_DES_ALGORITHM, BCRYPT_MD5_ALGORITHM);
	}

	TEST_METHOD(Des3)
	{
		process(BCRYPT_3DES_ALGORITHM, BCRYPT_SHA256_ALGORITHM);
	}

	void process(wchar_t const * algorithm, wchar_t const * hashType)
	{
		auto p = wc::open_provider(algorithm);
		auto key = wc::create_key(p, wc::hash_text(hashType, "Hello World"));
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