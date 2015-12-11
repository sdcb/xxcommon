#include <CppUnitTest.h>
#include <_fun/add.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace _Fun
{		
	TEST_CLASS(AddTest)
	{
	public:
		TEST_METHOD(AddSimple)
		{
			Assert::AreEqual(5, add(2, 3));
		}
	};
}