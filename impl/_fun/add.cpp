#include "add.h"

auto add(int a, int b) -> decltype(a + b)
{
	return a + b;
}