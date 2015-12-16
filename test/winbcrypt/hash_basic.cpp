#include <CppUnitTest.h>
#include <winbcrypt\winbcrypt.h>
#include <string>
#include "text_util\text_util.h"
#include <boost\algorithm\hex.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std::string_literals;
using namespace text_util;
namespace wc = winbcrypt;

TEST_CLASS(Winbcrypt_Hash)
{
	TEST_METHOD(Md5)
	{
		CheckAlgorithm(BCRYPT_MD5_ALGORITHM, "b10a8db164e0754105b7a99be72e3fe5");
	}

	TEST_METHOD(Sha256)
	{
		CheckAlgorithm(BCRYPT_SHA256_ALGORITHM, "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");
	}

	TEST_METHOD(Sha1)
	{
		CheckAlgorithm(BCRYPT_SHA1_ALGORITHM, "0a4d55a8d778e5022fab701977c5d840bbc486d0");
	}

	TEST_METHOD(Sha512)
	{
		CheckAlgorithm(BCRYPT_SHA512_ALGORITHM,
			"2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f2"
			"7e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b");
	}

	void CheckAlgorithm(wchar_t const * hashName, std::string expect)
	{
		auto hashed = wc::hash_text(hashName, "Hello World"s);

		std::string hexed;
		boost::algorithm::hex(hashed, std::back_inserter(hexed));

		Assert::AreEqual(expect.c_str(), hexed.c_str(), true);
	}
};