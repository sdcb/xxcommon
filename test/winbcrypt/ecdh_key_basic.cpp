#include <CppUnitTest.h>
#include <winbcrypt\winbcrypt.h>
#include "text_util\text_util.h"
#include <boost\format.hpp>

namespace wc = winbcrypt;
namespace tu = text_util;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std::string_literals;

TEST_CLASS(Winbcrypt_EcdhKeyBasic)
{
public:
	TEST_METHOD(CreateKey)
	{
		auto p = wc::open_provider(BCRYPT_ECDH_P256_ALGORITHM);
		auto k1 = wc::create_asymmetric_key(p);
		auto k2 = wc::create_asymmetric_key(p);

		auto sk1 = wc::export_key(k1, BCRYPT_PRIVATE_KEY_BLOB);
		auto pk2 = wc::export_key(k2, BCRYPT_PUBLIC_KEY_BLOB);

		auto hash = wc::get_agreement(k1, k2);

		log(sk1, "sk1");
		log(pk2, "pk2");
		log(hash, "hash");
	}

	TEST_METHOD(ImportKey)
	{
		auto hash_64 = "GS7y5Uv3qLNX2ityZgHRJI78eIVIh6LB92vNacCrHkI="s;
		auto pk2_64 = "RUNLMSAAAACA0uDfS9Cf3MFpl8czi6p0t+/s8WtQqdT/NophNk239PPTuAQz7g8f4/3TUh6O4Pir5knvP7aDo6ud7PB7kglO"s;
		auto sk1_64 = "RUNLMiAAAAC5K/4eqjbOPkHCyukcTuLJmPipgF9CVzLoa1Dh8lSkynpJIdFqhbJvIZ+1nPMWtbaV+CH0R9xRCMKygrOqGdi6"
			"OtwsZAU6yXdhYAf7nWlOaH7u63kwBYVS4ZV+i1+wmZc="s;

		auto p = wc::open_provider(BCRYPT_ECDH_P256_ALGORITHM);
		auto sk1 = wc::import_key(p, BCRYPT_PRIVATE_KEY_BLOB, tu::decode64(sk1_64));
		auto pk2 = wc::import_key(p, BCRYPT_PUBLIC_KEY_BLOB, tu::decode64(pk2_64));

		auto hash = wc::get_agreement(sk1, pk2);
		auto hash64 = tu::encode64(hash);

		Assert::AreEqual(hash64, hash_64);
	}

	void log(std::vector<byte> blob, std::string && prefix = ""s)
	{
		Logger::WriteMessage((boost::format("%1%(%2%): %3%\n")
			% prefix 
			% blob.size() 
			% tu::encode64(blob)).str().c_str());
	}
};