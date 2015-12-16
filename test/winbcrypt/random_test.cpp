#include <CppUnitTest.h>
#include <winbcrypt\winbcrypt.h>
#include <array>
#include <sstream>
#include <text_util\text_util.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace winbcrypt;
using namespace text_util;

TEST_CLASS(Winbcrypt_Random)
{
public:
	TEST_METHOD(Array)
	{
		std::array<byte, 16> buffer;
		random(buffer);
		Logger::WriteMessage((encode64(to_buffer(buffer)) + "\n").c_str());
	}

	TEST_METHOD(Vector)
	{
		std::vector<byte> buffer;
		buffer.resize(16);
		random(&buffer[0], buffer.size());
		Logger::WriteMessage(encode64(buffer).c_str());
	}

	TEST_METHOD(Primitive)
	{
		int a, b, c;
		random(a);
		random(b);
		random(c);

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