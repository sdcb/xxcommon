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
	TEST_METHOD(ArrayBuffer)
	{
		auto p = open_provider(BCRYPT_RNG_ALGORITHM);

		{
			std::array<byte, 16> buffer;
			random(p, buffer);
			Logger::WriteMessage((encode64(buffer) + "\n").c_str());
		}
		
		{
			std::vector<byte> buffer;
			buffer.resize(16);
			random(p, &buffer[0], static_cast<uint32_t>(buffer.size()));
			Logger::WriteMessage(encode64(buffer).c_str());
		}
	}

	TEST_METHOD(Primitive)
	{
		auto p = open_provider(BCRYPT_RNG_ALGORITHM);
		std::stringstream ss;

		for (auto i = 1; i <= 100; ++i)
		{
			byte a;
			random(p, a);
			ss << (int)a << "\t";

			if (i % 10 == 0) ss << std::endl;
		}

		Logger::WriteMessage(ss.str().c_str());	
	}
};