#include <CppUnitTest.h>
#include <wincrypt\wincrypt.h>

using namespace wincrypt;

TEST_CLASS(Wincrypt_EcdhKeyBasic)
{
public:
	TEST_METHOD(Basic)
	{
		auto p = open_provider(BCRYPT_ECDH_P256_ALGORITHM);
		auto k = create_asymmetric_key(p);
		auto pk = export_key(k, BCRYPT_ECCPUBLIC_BLOB);
		auto sk = export_key(k, BCRYPT_ECCPRIVATE_BLOB);
	}
};