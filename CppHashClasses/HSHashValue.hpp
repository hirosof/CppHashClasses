#pragma once

#include "HSHashException.hpp"
#include <cstdio>
#include <string>

BEGIN_HSHASH_NAMESPACE

namespace Base {

	template <typename T, size_t TElementSize , size_t lastLimitSize = sizeof(T)> class CHashValueBase {

	private:
		T m_hashValue[TElementSize];


	public:

		using ElementType = T;
		static const size_t ElementSize = TElementSize;

		CHashValueBase (void) {

		}

		CHashValueBase (const T (&hashValue)[TElementSize]) {
			for (size_t i = 0; i < TElementSize; i++){
				m_hashValue[i] = hashValue[i];
			}
		}


		CHashValueBase& operator=(const CHashValueBase& value) {
			for (size_t i = 0; i < TElementSize; i++){
				m_hashValue[i] = value.m_hashValue[i];
			}
			return *this;
		}

		static size_t GetSize (void) {
			return sizeof (m_hashValue) -(sizeof (T) - lastLimitSize);
		}

		static size_t GetWordSize (void) {
			return sizeof (T);
		}

		static size_t CountWordElements (void) {
			return TElementSize;
		}

		static size_t Count (void) {
			return GetSize ();
		}


		T GetWordValue (size_t index) const {
			if (index >= TElementSize) throw Exception::COutOfRangeExceptionSizeT (index, 0, TElementSize - 1);
			T value = m_hashValue[index];
			if (index == TElementSize - 1) {
				if (GetWordSize () != lastLimitSize) {
					size_t invalidBytesSize = GetWordSize () - lastLimitSize;
					T mask = 0xFF;
					for (size_t i = 1; i < invalidBytesSize; i++)
					{
						mask <<= 8;
						mask |= 0xFF;
					}
					value &= ~mask;
				}
			}
			return value;
		}

		uint8_t GetValue (size_t index) const{
			const size_t wordSize = GetWordSize ();
			if (index >= GetSize()) throw Exception::COutOfRangeExceptionSizeT (index, 0, GetSize () - 1);
			size_t valueIndex = index / wordSize;
			size_t byteIndex = wordSize - 1 - (index % wordSize);
			T wordValue = GetWordValue (valueIndex);
			return (wordValue >> (byteIndex * 8)) & 0xFF;
		}

		const uint8_t operator[](size_t index) const {
			return GetValue (index);
		}

		
		::std::string ToString (void) const {
			char text[3];
			::std::string s;
			for (size_t i = 0; i < this->Count(); i++){
				sprintf_s (text, "%02x", this->GetValue (i));
				s += text;
			}
			return s;
		}

		::std::wstring ToWString (void) const {
			wchar_t text[3];
			::std::wstring s;
			for (size_t i = 0; i < this->Count(); i++){
				swprintf_s (text, L"%02x", this->GetValue (i));
				s += text;
			}
			return s;
		}

	};

}

END_HSHASH_NAMESPACE