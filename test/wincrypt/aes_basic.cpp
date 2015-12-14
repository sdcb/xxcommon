#include <CppUnitTest.h>
#include <wincrypt\wincrypt.h>
#include <text64\text64.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std::string_literals;
namespace wc = wincrypt;

TEST_CLASS(Wincrypt_Aes)
{
	TEST_METHOD(Aes256)
	{
		auto p = wc::open_provider(BCRYPT_AES_ALGORITHM);
		auto hash = wc::hash_text(BCRYPT_SHA256_ALGORITHM, "Hello World");
		auto key = wc::create_key(p, hash);
		auto iv = wc::random_blob(16);
		auto plain = "Hello World"s;

		auto cipher = wc::encrypt(key, std::vector<byte>(&plain[0], &plain[0] + plain.size()), iv);
		auto decrypted = wc::decrypt(key, cipher, iv);
		auto decryptedText = std::string(decrypted.begin(), decrypted.end());
		
		Assert::AreEqual(decryptedText, plain);
	}

	TEST_METHOD(Aes128)
	{
		auto p = wc::open_provider(BCRYPT_AES_ALGORITHM);
		auto hash = wc::hash_text(BCRYPT_MD5_ALGORITHM, "Hello World");
		auto key = wc::create_key(p, hash);
		auto iv = wc::random_blob(16);
		auto plain = "Hello World"s;

		auto cipher = wc::encrypt(key, std::vector<byte>(&plain[0], &plain[0] + plain.size()), iv);
		auto decrypted = wc::decrypt(key, cipher, iv);
		auto decryptedText = std::string(decrypted.begin(), decrypted.end());

		Assert::AreEqual(decryptedText, plain);
	}

	TEST_METHOD(DesX3)
	{
		auto p = wc::open_provider(BCRYPT_3DES_ALGORITHM);
		auto hash = wc::hash_text(BCRYPT_SHA256_ALGORITHM, "Hello World");
		auto key = wc::create_key(p, hash);
		auto iv = wc::random_blob(16);
		auto plain = "Hello World"s;

		auto cipher = wc::encrypt(key, std::vector<byte>(&plain[0], &plain[0] + plain.size()), iv);
		auto decrypted = wc::decrypt(key, cipher, iv);
		auto decryptedText = std::string(decrypted.begin(), decrypted.end());

		Assert::AreEqual(decryptedText, plain);
	}
};