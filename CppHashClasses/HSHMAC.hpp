#pragma once

#include "HSSHA1.hpp"
#include "HSSHA2.hpp"



BEGIN_HSHASH_NAMESPACE




namespace HMAC {

	template <typename HashAlgorithm> class CHMACKey {
	private:
		uint8_t m_key[HashAlgorithm::m_MessageBlockSize];
	public:

		using CHash = HashAlgorithm;

		static const size_t m_KeySize = HashAlgorithm::m_MessageBlockSize;


		CHMACKey () {
			for (size_t i = 0; i < m_KeySize; i++)
			{
				m_key[i] = 0;
			}
		}

		CHMACKey (const uint8_t (&key)[m_KeySize]){
			for (size_t i = 0; i < m_KeySize; i++)
			{
				m_key[i] = key[i];
			}
		}

		CHMACKey& operator=(const CHMACKey& key) {
			for (size_t i = 0; i < m_KeySize; i++) {
				m_key[i] = key.m_key[i];
			}
			return *this;
		}

		static size_t Count (void) {
			return m_KeySize;
		}

		uint8_t GetValue (size_t index) const {
			if (index >= m_KeySize) throw Exception::COutOfRangeExceptionSizeT (index, 0, m_KeySize - 1);
			return this->m_key[index];
		}

		const uint8_t operator[](size_t index) const {
			return GetValue (index);
		}

	};


	template <typename HashAlgorithm> class CHMACKeyBuilder {
	private:
		uint8_t m_keyBuffer[HashAlgorithm::m_MessageBlockSize];
		uint64_t m_KeySaltSize;
		HashAlgorithm m_hash;
		EComputeState State;
	public:
		using CKeyType = CHMACKey <HashAlgorithm>;
		using CHash = HashAlgorithm;

		CHMACKeyBuilder () {
			this->Reset ();

		}


		void Reset (void) {
			m_KeySaltSize = 0;
			m_hash.Reset ();
			State = EComputeState::Updatable;
		}

		bool IsUpdatable (void) const {
			return State == EComputeState::Updatable;
		}

		bool IsFilaziled (void) const {
			return State == EComputeState::Finalized;
		}

		bool Update (const void *pData, uint64_t dataSize) {
			if (State != EComputeState::Updatable) return false;
			if (pData == nullptr)return false;
			if (dataSize == 0)return false;

			const uint8_t *lpBytesData = static_cast<const uint8_t*>(pData);

			if (m_KeySaltSize > HashAlgorithm::m_MessageBlockSize) {
				m_hash.Update (pData, dataSize);
			} else  if(m_KeySaltSize + dataSize > HashAlgorithm::m_MessageBlockSize){
				m_hash.Update (m_keyBuffer, m_KeySaltSize);
				m_hash.Update (lpBytesData, dataSize);
			} else {
				memcpy (&this->m_keyBuffer[this->m_KeySaltSize], lpBytesData, static_cast<size_t>(dataSize));
			}

			this->m_KeySaltSize += dataSize;

			return true;
		}

		bool Update (const char *pString) {
			if (pString == nullptr) return false;
			return this->Update (pString, strlen (pString));
		}

		bool Update (const wchar_t *pString) {
			if (pString == nullptr) return false;
			return this->Update (pString, wcslen (pString));
		}

		bool Compute (const void *pData, uint64_t dataSize) {
			if (pData == nullptr) return false;
			if (dataSize > 0) {
				if (this->Update (pData, dataSize) == false) {
					return false;
				}
			}
			return this->Finalize ();
		}

		bool Compute (const char *pString) {
			if (pString == nullptr) return false;
			return this->Compute (pString, strlen (pString));
		}

		bool Compute (const wchar_t *pString) {
			if (pString == nullptr) return false;
			return this->Compute (pString, wcslen (pString));
		}

		bool Finalize (void) {
			if (State != EComputeState::Updatable) return false;

			if (m_KeySaltSize <= HashAlgorithm::m_MessageBlockSize) {
				memset (&this->m_keyBuffer[this->m_KeySaltSize], 0, static_cast<size_t>(HashAlgorithm::m_MessageBlockSize - m_KeySaltSize));
			} else {

				if (m_hash.Finalize () == false) return false;

				typename CHash::HashValueType value;

				if (m_hash.GetHash (&value) == false) return false;

				memset (&this->m_keyBuffer[0], 0, HashAlgorithm::m_MessageBlockSize);


				for (size_t i = 0; i < value.Count(); i++)
				{
					this->m_keyBuffer[i] = value[i];
				}
			}

			State = EComputeState::Finalized;

			return true;

		}

		bool GetKey (CKeyType *pKey) const {
			if (this->State != EComputeState::Finalized) return false;
			if (pKey != nullptr) {
				*pKey = CKeyType (this->m_keyBuffer);
				return true;
			}
			return false;
		};

	};


	template <typename HashAlgorithm> class CHMAC : public Base::CHashBase<typename HashAlgorithm::HashValueType> {
	public:
		using CHash = HashAlgorithm;
		using CKeyType = CHMACKey <HashAlgorithm>;
		using CKeyBuilder = CHMACKeyBuilder<HashAlgorithm>;
	private:

		CKeyType m_key;
		CHash  m_ihash;
		CHash  m_ohash;
		EComputeState State;
	public:
		

		CHMAC () {
			Reset ();
		}

		CHMAC (const CKeyBuilder &keybuilder) {

			CKeyBuilder  builder (keybuilder);

			if (builder.IsUpdatable ()) builder.Finalize ();

			CKeyType key;

			if (builder.GetKey (&key)) {
				m_key = key;
			}

			Reset ();
		}

		CHMAC (const CKeyType &key) {
			m_key = key;
			Reset ();
		}

		void Reset (void) {
			m_ihash.Reset ();
			for (size_t i = 0; i < CHash::m_MessageBlockSize; i++)
			{
				uint8_t u = m_key[i] ^ 0x36;
				m_ihash.Update (&u , sizeof (uint8_t));
			}
			State = EComputeState::Updatable;
		}

		bool Update (const void *pData, uint64_t dataSize) {
			if (this->State != EComputeState::Updatable) return false;
			return this->m_ihash.Update (pData, dataSize);
		}

		bool Update (const char *pString) {
			return Base::CHashBase<typename HashAlgorithm::HashValueType>::Update (pString);
		}

		bool Update (const wchar_t *pString) {
			return Base::CHashBase<typename HashAlgorithm::HashValueType>::Update (pString);
		}

		bool Finalize (void) {
			if (this->State != EComputeState::Updatable) return false;
			
			this->m_ihash.Finalize ();

			m_ohash.Reset ();
			for (size_t i = 0; i < CHash::m_MessageBlockSize; i++)
			{
				uint8_t u = m_key[i] ^ 0x5c;
				m_ohash.Update (&u , sizeof (uint8_t));
			}


			typename CHash::HashValueType ivalue;

			m_ihash.GetHash (&ivalue);

			for (size_t i = 0; i < ivalue.Count(); i++)
			{
				uint8_t u = ivalue.GetValue (i);
				m_ohash.Update (&u, sizeof (uint8_t));
			}


			m_ohash.Finalize ();

			State = EComputeState::Finalized;
			return true;
		}

		bool GetHash (typename CHash::HashValueType  *pHash) const {
			if (this->State != EComputeState::Finalized) return false;
			return this->m_ohash.GetHash (pHash);
		}


	};


	using CHMACKeySHA1 = CHMACKey<CSHA1>;
	using CHMACKeySHA224 = CHMACKey<CSHA224>;
	using CHMACKeySHA256 = CHMACKey<CSHA256>;
	using CHMACKeySHA384 = CHMACKey<CSHA384>;
	using CHMACKeySHA512 = CHMACKey<CSHA512>;
	using CHMACKeySHA512Per224 = CHMACKey<CSHA512Per224>;
	using CHMACKeySHA512Per256 = CHMACKey<CSHA512Per256>;

	using CHMACKeySHA1Builder = CHMACKeyBuilder<CSHA1>;
	using CHMACKeySHA224Builder = CHMACKeyBuilder<CSHA224>;
	using CHMACKeySHA256Builder = CHMACKeyBuilder<CSHA256>;
	using CHMACKeySHA384Builder = CHMACKeyBuilder<CSHA384>;
	using CHMACKeySHA512Builder = CHMACKeyBuilder<CSHA512>;
	using CHMACKeySHA512Per224Builder = CHMACKeyBuilder<CSHA512Per224>;
	using CHMACKeySHA512Per256Builder = CHMACKeyBuilder<CSHA512Per256>;

	using CHMACSHA1 = CHMAC<CSHA1>;
	using CHMACSHA224 = CHMAC<CSHA224>;
	using CHMACSHA256 = CHMAC<CSHA256>;
	using CHMACSHA384 = CHMAC<CSHA384>;
	using CHMACSHA512 = CHMAC<CSHA512>;
	using CHMACSHA512Per224 = CHMAC<CSHA512Per224>;
	using CHMACSHA512Per256 = CHMAC<CSHA512Per256>;
}

END_HSHASH_NAMESPACE