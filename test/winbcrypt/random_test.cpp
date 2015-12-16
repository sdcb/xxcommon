#include <CppUnitTest.h>
#include <winbcrypt\winbcrypt.h>
#include <array>
#include <sstream>
#include <text64\text64.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace winbcrypt;

TEST_CLASS(Winbcrypt_Random)
{
public:
	TEST_METHOD(Array)
	{
		auto p = open_provider(BCRYPT_RNG_ALGORITHM);

		std::array<byte, 16> buffer;
		random(p, buffer);
		Logger::WriteMessage((encode64(buffer) + "\n").c_str());
	}

	TEST_METHOD(Vector)
	{
		auto p = open_provider(BCRYPT_RNG_ALGORITHM);

		std::vector<byte> buffer;
		buffer.resize(16);
		random(p, &buffer[0], buffer.size());
		Logger::WriteMessage(encode64(buffer).c_str());
	}

	TEST_METHOD(Primitive)
	{
		auto p = open_provider(BCRYPT_RNG_ALGORITHM);
		int a, b, c;
		random(p, a);
		random(p, b);
		random(p, c);

		Assert::AreNotEqual(a, b);
		Assert::AreNotEqual(a, c);
		Logger::WriteMessage(std::to_string(a).c_str());
		Logger::WriteMessage(std::to_string(b).c_str());
		Logger::WriteMessage(std::to_string(c).c_str());
	}

	TEST_METHOD(GenerateBlob)
	{
		auto blob1 = encode64(random_blob(32));
		auto blob2 = encode64(random_blob(32));

		Assert::AreNotEqual(blob1, blob2);
	}
};