#pragma once

#include <vector>
#include <string>

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

std::string encode64(const std::vector<unsigned char> &val);

template <size_t Size>
std::string encode64(const std::array<unsigned char, Size> &val)
{
	using namespace boost::archive::iterators;
	using It = base64_from_binary<transform_width<std::array<unsigned char, Size>::const_iterator, 6, 8>>;
	auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
	return tmp.append((3 - val.size() % 3) % 3, '=');
}

std::vector<unsigned char> decode64(const std::string &val);
