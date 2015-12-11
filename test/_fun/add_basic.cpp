#include <CppUnitTest.h>
#include <_fun/add.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

TEST_CLASS(Fun_AddTest)
{
public:
	TEST_METHOD(AddSimple)
	{
		Assert::AreEqual(5, add(2, 3));
	}
};