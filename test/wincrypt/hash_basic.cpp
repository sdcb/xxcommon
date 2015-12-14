#include <CppUnitTest.h>
#include <wincrypt\wincrypt.h>
#include <string>
#include <text64\text64.h>
#include <boost\algorithm\hex.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std::string_literals;
namespace wc = wincrypt;

TEST_CLASS(Wincrypt_Hash)
{
	TEST_METHOD(Md5)
	{
		auto p = wc::open_provider(BCRYPT_MD5_ALGORITHM);
		auto md5 = wc::create_hash(p);
		
		auto plain = "Hello World"s;
		wc::combine(md5, 
			static_cast<void *>(&plain[0]), 
			plain.size());

		auto hashed = wc::get_hashed(md5);

		std::string hexed;
		boost::algorithm::hex(hashed, std::back_inserter(hexed));

		Assert::AreEqual("b10a8db164e0754105b7a99be72e3fe5", hexed.c_str(), true);
	}
};