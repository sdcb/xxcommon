#include <CppUnitTest.h>
#include <wincrypt\wincrypt.h>
#include <array>
#include <sstream>
#include <text64\text64.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace wincrypt;

TEST_CLASS(Wincrypt_Random)
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
		random(p, &buffer[0], static_cast<uint32_t>(buffer.size()));
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
	}

	TEST_METHOD(GenerateBlob)
	{
		auto blob1 = random_blob(32);
		auto blob2 = random_blob(32);

		Assert::AreNotEqual(encode64(blob1), encode64(blob2));
	}
};