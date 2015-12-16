#pragma once

#include <vector>
#include <string>

namespace text_util {
	std::string encode64(const std::vector<unsigned char> &val);

	std::vector<unsigned char> decode64(const std::string &val);

	template <size_t Size>
	std::vector<unsigned char> to_buffer(std::array<unsigned char, Size> const & buffer)
	{
		std::vector<unsigned char> v(Size);
		std::copy_n(buffer.cbegin(), buffer.size(), v.begin());
		return v;
	}
}