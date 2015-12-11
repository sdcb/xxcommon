#include <CppUnitTest.h>
#include <wincrypt\wincrypt.h>
#include <array>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace wincrypt;

TEST_CLASS(Wincrypt_Random)
{
public:
	TEST_METHOD(Basic)
	{
		auto p = open_provider(BCRYPT_RNG_ALGORITHM);

		std::array<byte, 16> buffer;

		random(p, buffer);
		random(p, buffer);
		random(p, buffer);
		random(p, buffer);
		random(p, buffer);
	}
};