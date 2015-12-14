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

	struct status_exception
	{
		NTSTATUS code;

		status_exception(NTSTATUS result) :
			code{ result }
		{
		}
	};

	auto check(NTSTATUS const status) -> void;

	auto open_provider(wchar_t const * algorithm)->provider;

	auto random(provider const & p,
		void * buffer,
		size_t size) -> void;

	auto random_blob(size_t size) -> std::vector<byte>;

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

	auto hash_text(wchar_t const * algorithm, const std::string & text)->std::vector<byte>;

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

	auto create_key(provider const & p,
		std::vector<byte> const & secret)->key;

	auto create_asymmetric_key(provider const & p,
		size_t keysize = 0)->key;

	auto export_key(key const & fk,
		wchar_t const * blobtype)->std::vector<byte>;
	
	auto import_key(provider const & p,
		wchar_t const * blobtype,
		const std::vector<byte> & keyBlob)->key;

	auto get_agreement(key const & fk,
		key const & pk,
		wchar_t const * hash_name = BCRYPT_SHA256_ALGORITHM)->std::vector<byte>;
	
	auto encrypt(key const & k,
		const std::vector<byte> & plaintext,
		std::vector<byte> iv,
		unsigned long flags = BCRYPT_BLOCK_PADDING)->std::vector<byte>;

	auto decrypt(key const & k,
		std::vector<byte> const & ciphertext,
		std::vector<byte> iv,
		unsigned long flags = BCRYPT_BLOCK_PADDING)->std::vector<byte>;
}