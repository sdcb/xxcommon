#include "text_util.h"

namespace text_util
{
	std::vector<unsigned char> to_buffer(std::string && text)
	{
		std::vector<unsigned char> buffer(text.size());
		buffer.assign(text.cbegin(), text.cend());
		return buffer;
	}
}