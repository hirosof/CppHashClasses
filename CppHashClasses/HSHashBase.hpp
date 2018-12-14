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

		virtual bool Update (const void *pData, uint64_t dataSize) = 0;
		
		bool UpdateString (const char *pString) {
			if (pString == nullptr) return false;
			return this->Update (pString, strlen (pString));
		}

		bool UpdateString (const wchar_t *pString) {
			if (pString == nullptr) return false;
			return this->Update (pString, wcslen (pString));
		}

		virtual bool Finalize (void) = 0;

		virtual bool GetHash (HashValueType *pHash) const = 0;

		bool Compute (const void *pData, uint64_t dataSize) {
			if (this->Update (pData, dataSize)) {
				return this->Finalize ();
			}
			return false;
		}

		bool ComputeString (const char *pString) {
			if (pString == nullptr) return false;
			return this->Compute (pString, strlen (pString));
		}

		bool ComputeString (const wchar_t *pString) {
			if (pString == nullptr) return false;
			return this->Compute (pString, wcslen (pString));
		}

	};

}

END_HSHASH_NAMESPACE