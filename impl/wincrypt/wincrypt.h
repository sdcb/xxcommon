#pragma once

#include "handle.h"
#include <bcrypt.h>
#include <vector>
#include <string>
#pragma comment(lib, "bcrypt")

namespace wincrypt
{
	struct provider_traits
	{
		using pointer = BCRYPT_ALG_HANDLE;

		static auto invalid() throw() -> pointer
		{
			return nullptr;
		}

		static auto close(pointer value) throw() -> void
		{
			VERIFY_(ERROR_SUCCESS, BCryptCloseAlgorithmProvider(value, 0));
		}
	};

	using provider = unique_handle<provider_traits>;

	struct status_exception : public std::exception
	{
		NTSTATUS code;
		std::string _what;

		status_exception(NTSTATUS result) :
			code{ result }, 
			_what{std::string("NTSTATUS = ") + std::to_string(code)}
		{
		}

		char const* what() const
		{
			return _what.c_str();
		}
	};

	auto check(NTSTATUS const status) -> void;

	auto open_provider(wchar_t const * algorithm)->provider;

	auto random(provider const & p,
		void * buffer,
		size_t size) -> void;

	template <typename T, size_t Count>
	auto random(provider const & p,
		T(&buffer)[Count]) -> void
	{
		static_assert(std::is_pod<T>::value, "T must be POD");

		random(p,
			buffer,
			sizeof(T)* Count);
	}

	template <typename T>
	auto random(provider const & p,
		T & buffer) -> void
	{
		static_assert(std::is_pod<T>::value, "T must be POD");

		random(p,
			&buffer,
			sizeof(T));
	}

	struct hash_traits
	{
		using pointer = BCRYPT_ALG_HANDLE;

		static auto invalid() throw() -> pointer
		{
			return nullptr;
		}

		static auto close(pointer value) throw() -> void
		{
			VERIFY_(ERROR_SUCCESS, BCryptDestroyHash(value));
		}
	};

	using hash = unique_handle<hash_traits>;

	auto create_hash(provider const & p)->hash;

	auto combine(hash const & h,
		void const * buffer,
		size_t size) -> void;

	template <typename T>
	auto get_property(BCRYPT_HANDLE handle,
		wchar_t const * name,
		T & value) -> void
	{
		auto bytesCopied = ULONG{};

		check(BCryptGetProperty(handle,
			name,
			reinterpret_cast<byte *>(&value),
			sizeof(T),
			&bytesCopied,
			0));
	}

	auto get_hashed(hash const & h,
		void * buffer,
		size_t size) -> void;

	auto get_hashed(hash const & h)->std::vector<byte>;

	struct key_traits
	{
		using pointer = BCRYPT_KEY_HANDLE;

		static auto invalid() throw() -> pointer
		{
			return nullptr;
		}

		static auto close(pointer value) throw() -> void
		{
			VERIFY_(ERROR_SUCCESS, BCryptDestroyKey(value));
		}
	};

	using key = unique_handle<key_traits>;


	auto create_key(provider const & p,
		void const * secret,
		size_t size)->key;

	auto create_asymmetric_key(provider const & p,
		size_t keysize = 0)->key;

	auto export_key(key const & fk,
		wchar_t const * blobtype)->std::vector<byte>;

	auto import_key(provider const & p,
		wchar_t const * blobtype,
		void const * blob,
		size_t blobsize)->key;

	auto get_agreement(key const & fk,
		key const & pk,
		wchar_t const * hash_name = BCRYPT_SHA256_ALGORITHM)->std::vector<byte>;

	auto encrypt(key const & k,
		void const * plaintext,
		size_t plaintext_size,
		void * ciphertext,
		size_t ciphertext_size,
		unsigned long flags) -> unsigned;

	template <typename String, typename Sequence>
	auto encrypt(key const & k,
		String const & plaintext,
		Sequence iv,
		unsigned long flags) -> std::vector<byte>
	{
		auto bytesCopied = ULONG{};

		check(BCryptEncrypt(
			k.get(),
			static_cast<byte *>(const_cast<void*>((const void *)&plaintext[0])),
			static_cast<unsigned>(plaintext.size() * sizeof(String::value_type)),
			nullptr,
			static_cast<byte *>(&iv[0]),
			static_cast<unsigned>(iv.size() * sizeof(Sequence::value_type)),
			nullptr,
			0,
			&bytesCopied,
			flags));

		auto ciphertext = vector<byte>(bytesCopied);

		check(BCryptEncrypt(
			k.get(),
			static_cast<byte *>(const_cast<void*>((const void *)&plaintext[0])),
			static_cast<unsigned>(plaintext.size() * sizeof(String::value_type)),
			nullptr,
			static_cast<byte *>(&iv[0]),
			static_cast<unsigned>(iv.size() * sizeof(Sequence::value_type)),
			static_cast<byte *>(&ciphertext[0]),
			static_cast<unsigned>(ciphertext.size()),
			&bytesCopied,
			flags));

		return ciphertext;
	}

	auto decrypt(key const & k,
		void const * ciphertext,
		size_t ciphertext_size,
		void * plaintext,
		size_t plaintext_size,
		unsigned long flags) -> unsigned;

	auto decrypt(key const & k,
		std::vector<byte> const & ciphertext,
		std::vector<byte> & iv,
		unsigned long flags)->std::vector<byte>;

	auto create_shared_secret(std::string const & secret)->std::vector<byte>;

	auto encrypt_message(wchar_t const * algorithm,
		std::vector<byte> const & shared,
		std::string const & plaintext)->std::vector<byte>;


	auto decrypt_message(wchar_t const * algorithm,
		std::vector<byte> const & shared,
		std::vector<byte> const & ciphertext)->std::string;
}