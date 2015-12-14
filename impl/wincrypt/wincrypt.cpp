#include "wincrypt.h"

using namespace std;

namespace wincrypt
{
	auto random(provider const & p,
		void * buffer,
		size_t size) -> void
	{
		check(BCryptGenRandom(p.get(),
			static_cast<byte *>(buffer),
			static_cast<ULONG>(size),
			0));
	}

	auto random_blob(size_t size)->std::vector<byte>
	{
		vector<byte> buffer(size);
		auto p = open_provider(BCRYPT_RNG_ALGORITHM);
		random(p, &buffer[0], buffer.size());
		return buffer;
	}

	auto create_hash(provider const & p) -> hash
	{
		auto h = hash{};

		check(BCryptCreateHash(p.get(),
			h.get_address_of(),
			nullptr,
			0,
			nullptr,
			0,
			0));

		return h;
	}

	auto combine(hash const & h,
		void const * buffer,
		size_t size) -> void
	{
		check(BCryptHashData(h.get(),
			static_cast<byte *>(const_cast<void *>(buffer)),
			static_cast<ULONG>(size),
			0));
	}

	auto get_hashed(hash const & h,
		void * buffer,
		size_t size) -> void
	{
		check(BCryptFinishHash(h.get(),
			static_cast<byte *>(buffer),
			static_cast<ULONG>(size),
			0));
	}

	auto get_hashed(hash const & h) -> std::vector<byte>
	{
		DWORD size;
		get_property(h.get(), BCRYPT_HASH_LENGTH, size);

		std::vector<byte> buffer(size);
		get_hashed(h, &buffer[0], size);

		return buffer;
	}

	auto hash_text(wchar_t const * algorithm, const std::string & text) -> std::vector<byte>
	{
		auto p = open_provider(algorithm);
		auto hashType = create_hash(p);

		combine(hashType,
			static_cast<const void *>(&text[0]),
			text.size());

		return get_hashed(hashType);
	}

	auto get_property(BCRYPT_HANDLE handle,
		wchar_t const * name) -> size_t
	{
		auto bytesCopied = ULONG{};
		auto value = size_t{};

		check(BCryptGetProperty(handle,
			name,
			reinterpret_cast<byte *>(&value),
			sizeof(size_t),
			&bytesCopied,
			0));

		return value;
	}

	auto create_key(provider const & p,
		void const * secret,
		size_t size) -> key
	{
		auto k = key{};

		check(BCryptGenerateSymmetricKey(
			p.get(),
			k.get_address_of(),
			nullptr,
			0,
			static_cast<byte *>(const_cast<void *>(secret)),
			static_cast<ULONG>(size),
			0));

		return k;
	}

	auto create_key(provider const & p,
		std::vector<byte> const & secret)->key
	{
		return create_key(p, &secret[0], secret.size());
	}

	auto create_asymmetric_key(provider const & p,
		size_t keysize) -> key
	{
		auto fk = key{};
		check(BCryptGenerateKeyPair(p.get(),
			fk.get_address_of(),
			static_cast<ULONG>(keysize),
			0));
		check(BCryptFinalizeKeyPair(fk.get(), 0));
		return fk;
	}

	auto export_key(key const & fk,
		wchar_t const * blobtype) -> std::vector<byte>
	{
		unsigned long publickey_size;
		check(BCryptExportKey(
			fk.get(),
			nullptr,
			blobtype,
			nullptr,
			0,
			&publickey_size,
			0));
		auto value = std::vector<byte>(publickey_size);
		check(BCryptExportKey(
			fk.get(),
			nullptr,
			blobtype,
			&value[0],
			publickey_size,
			&publickey_size,
			0));

		return value;
	}

	auto import_key(provider const & p,
		wchar_t const * blobtype,
		const vector<byte> & keyBlob)->key
	{
		key k;
		check(BCryptImportKeyPair(
			p.get(),
			nullptr,
			blobtype,
			k.get_address_of(),
			static_cast<PUCHAR>(const_cast<byte *>(&keyBlob[0])),
			static_cast<ULONG>(keyBlob.size()),
			0));
		
		return k;
	}

	auto get_agreement(key const & fk,
		key const & pk,
		wchar_t const * hash_name) -> std::vector<byte>
	{
		BCRYPT_SECRET_HANDLE handle;
		check(BCryptSecretAgreement(
			fk.get(),
			pk.get(),
			&handle,
			0));

		wstring hash_name_string = hash_name;

		BCryptBuffer bcrypt_buffers[] =
		{
			{
				static_cast<uint32_t>(hash_name_string.size() * 2 + 2),
				KDF_HASH_ALGORITHM,
				&hash_name_string[0],
			}
		};
		BCryptBufferDesc params =
		{
			BCRYPTBUFFER_VERSION,
			_countof(bcrypt_buffers),
			bcrypt_buffers,
		};

		unsigned long derivedkey_size;
		check(BCryptDeriveKey(
			handle,
			BCRYPT_KDF_HASH,
			&params,
			nullptr,
			0,
			&derivedkey_size,
			0));

		auto value = std::vector<byte>(derivedkey_size);
		check(BCryptDeriveKey(
			handle,
			BCRYPT_KDF_HASH,
			&params,
			&value[0],
			derivedkey_size,
			&derivedkey_size,
			0));

		check(BCryptDestroySecret(handle));
		return value;
	}

	auto encrypt(key const & k,
		const std::vector<byte> & plaintext,
		std::vector<byte> iv,
		unsigned long flags) -> std::vector<byte>
	{
		auto bytesCopied = ULONG{};

		check(BCryptEncrypt(
			k.get(),
			const_cast<byte*>(&plaintext[0]),
			static_cast<ULONG>(plaintext.size()),
			nullptr,
			const_cast<byte *>(&iv[0]),
			static_cast<ULONG>(iv.size()),
			nullptr,
			0,
			&bytesCopied,
			flags));

		auto ciphertext = std::vector<byte>(bytesCopied);

		check(BCryptEncrypt(
			k.get(),
			const_cast<byte *>(&plaintext[0]),
			static_cast<ULONG>(plaintext.size()),
			nullptr,
			const_cast<byte *>(&iv[0]),
			static_cast<ULONG>(iv.size()),
			static_cast<byte *>(&ciphertext[0]),
			static_cast<unsigned>(ciphertext.size()),
			&bytesCopied,
			flags));

		return ciphertext;
	}

	auto decrypt(key const & k,
		vector<byte> const & ciphertext,
		vector<byte> iv,
		unsigned long flags)->vector<byte>
	{
		auto bytesCopied = unsigned long{};

		check(BCryptDecrypt(
			k.get(),
			static_cast<PUCHAR>(const_cast<PUCHAR>(&ciphertext[0])),
			static_cast<ULONG>(ciphertext.size()),
			nullptr,
			static_cast<PUCHAR>(const_cast<PUCHAR>(&iv[0])),
			static_cast<ULONG>(iv.size()),
			nullptr,
			0,
			&bytesCopied,
			flags));

		auto plaintext = vector<byte>(bytesCopied);

		check(BCryptDecrypt(
				k.get(),
				static_cast<PUCHAR>(const_cast<PUCHAR>(&ciphertext[0])),
				static_cast<ULONG>(ciphertext.size()),
				nullptr,
				static_cast<PUCHAR>(const_cast<PUCHAR>(&iv[0])),
				static_cast<ULONG>(iv.size()),
				static_cast<PUCHAR>(const_cast<PUCHAR>(&plaintext[0])),
				static_cast<ULONG>(plaintext.size()),
				&bytesCopied,
				flags));

		plaintext.resize(bytesCopied);
		return plaintext;
	}

	auto check(NTSTATUS const status) -> void
	{
		if (status != ERROR_SUCCESS)
		{
#if _DEBUG
			TRACE(L"NTSTATUS = 0x%x\n", status);
#endif
			throw status_exception{ status };
		}
	}

	auto open_provider(wchar_t const * algorithm) -> provider
	{
		auto p = provider{};
		check(BCryptOpenAlgorithmProvider(
			p.get_address_of(),
			algorithm,
			nullptr,
			0));
		return p;
	}
}