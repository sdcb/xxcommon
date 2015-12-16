#include "text_util.h"

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

namespace text_util {
	typedef unsigned char byte;

	std::string encode64(const std::vector<byte> &val) {
		using namespace boost::archive::iterators;
		using It = base64_from_binary<transform_width<std::vector<unsigned char>::const_iterator, 6, 8>>;
		auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
		return tmp.append((3 - val.size() % 3) % 3, '=');
	}

	std::vector<byte> decode64(const std::string &val)
	{
		using namespace boost::archive::iterators;
		using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
		return boost::algorithm::trim_right_copy_if(std::vector<unsigned char>(It(std::begin(val)), It(std::end(val))), [](char c) {
			return c == '\0';
		});
	}
}