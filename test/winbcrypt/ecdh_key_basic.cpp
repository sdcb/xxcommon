#include <CppUnitTest.h>
#include <winbcrypt\winbcrypt.h>
#include <text64\text64.h>
#include <boost\format.hpp>

using namespace winbcrypt;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

TEST_CLASS(Winbcrypt_EcdhKeyBasic)
{
public:
	TEST_METHOD(Basic)
	{
		auto p = open_provider(BCRYPT_ECDH_P256_ALGORITHM);
		auto k = create_asymmetric_key(p);
		auto pk = export_key(k, BCRYPT_ECCPUBLIC_BLOB);
		auto sk = export_key(k, BCRYPT_ECCPRIVATE_BLOB);

		Logger::WriteMessage(
			(boost::format("PK: %2% %1%\n") % encode64(pk) % pk.size()).str().c_str());

		Logger::WriteMessage(
			(boost::format("SK: %2% %1%\n") % encode64(sk) % sk.size()).str().c_str());
	}
};