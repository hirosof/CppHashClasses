#pragma once

#include "HSHashValue.hpp"

BEGIN_HSHASH_NAMESPACE

namespace Base {


	template <typename tnHashValueType>  class CHashBase {
	protected:

		EComputeState State;

	public:

		using HashValueType = tnHashValueType;
	

		virtual void Reset (void) = 0;


		virtual bool Update (const void *pData, uint64_t dataSize) {
			return false;
		}
		
		virtual bool Update (const char *pString) {
			if (pString == nullptr) return false;
			return this->Update (pString, strlen (pString) * sizeof (char));
		}

		virtual bool Update (const wchar_t *pString) {
			if (pString == nullptr) return false;
			return this->Update (pString, wcslen (pString) * sizeof(wchar_t));
		}

		virtual bool Finalize (void) = 0;

		virtual bool GetHash (HashValueType *pHash) const = 0;

		virtual bool Compute (const void *pData, uint64_t dataSize) {
			if (pData == nullptr) return false;
			if (dataSize > 0) {
				if (this->Update (pData, dataSize) == false) {
					return false;
				}
			}
			return this->Finalize ();
		}

		virtual bool Compute (const char *pString) {
			if (pString == nullptr) return false;
			return this->Compute (pString, strlen (pString) * sizeof (char));
		}

		virtual bool Compute (const wchar_t *pString) {
			if (pString == nullptr) return false;
			return this->Compute (pString, wcslen (pString) * sizeof (wchar_t));
		}

	};

	template <size_t MessageBlockSize, typename MessageSizeType, typename HashValueType>
	class CHashBaseWithMessageBlock : public CHashBase< HashValueType> {
	
	protected:
		uint8_t m_MessageBlock[MessageBlockSize];
		MessageSizeType  m_AllMessageSize;
		size_t m_MessageAddPosition;

		virtual void BlockProcess (void) = 0;
		virtual void MessageBufferProcess (void) {
			BlockProcess ();
			m_AllMessageSize += MessageBlockSize;
		}

	public:

		static const size_t m_MessageBlockSize = MessageBlockSize;

		CHashBaseWithMessageBlock () {
			Reset ();
		}

		virtual void Reset (void) {
			m_MessageAddPosition = 0;
			m_AllMessageSize = 0;
		}

	};
}

END_HSHASH_NAMESPACE