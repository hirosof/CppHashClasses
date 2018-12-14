#pragma once
#include "HSHashBase.hpp"
#include <memory>

BEGIN_HSHASH_NAMESPACE

namespace Base {

	template <size_t MessageBlockSize , typename MessageSizeType ,typename HashValueType> 
	class CSHABase : public CHashBaseWithMessageBlock<MessageBlockSize , MessageSizeType ,  HashValueType> {
	private:
		using BaseType = CHashBaseWithMessageBlock<MessageBlockSize, MessageSizeType, HashValueType>;
	public:


		virtual bool Update (const void *pData, uint64_t dataSize) {
			if (this->State != EComputeState::Updatable) return false;
			if (pData == nullptr) return false;
			if (dataSize == 0)return false;
			
			const uint8_t *lpBytesData = static_cast<const uint8_t*>(pData);
			
			if (this->m_MessageAddPosition + dataSize >= MessageBlockSize) {

				size_t addfirstSize = MessageBlockSize - this->m_MessageAddPosition;

				memcpy (&this->m_MessageBlock[this->m_MessageAddPosition], lpBytesData, addfirstSize);

				this->MessageBufferProcess ();
				uint64_t NumBlock = (dataSize - addfirstSize) / MessageBlockSize;
				size_t NumRest = (dataSize - addfirstSize) % MessageBlockSize;
				const uint8_t *lpRestBytesData = lpBytesData + addfirstSize;

				for (uint64_t i = 0; i < NumBlock; i++) {
					memcpy (&this->m_MessageBlock[0], lpRestBytesData + MessageBlockSize*i, MessageBlockSize);
					this->MessageBufferProcess ();
				}
				memcpy (&this->m_MessageBlock[0], lpRestBytesData + MessageBlockSize*NumBlock, NumRest);
			} else {
				memcpy (&this->m_MessageBlock[this->m_MessageAddPosition], pData, static_cast<size_t>(dataSize));
			}
			this->m_MessageAddPosition  = (this->m_MessageAddPosition + dataSize) % MessageBlockSize;

			return true;
		}

		virtual bool Update (const char *pString) {
			return BaseType::Update (pString);
		}
		virtual bool Update (const wchar_t *pString) {
			return BaseType::Update (pString);
		}

	};

	template <typename HashValueType> class CSHABase32BitUnit : public  CSHABase<64, uint64_t, HashValueType> {
	public:

		virtual bool Finalize (void) {
			if (this->State != EComputeState::Updatable) return false;

			uint64_t finalDataSize = this->m_AllMessageSize + this->m_MessageAddPosition;
			uint64_t finalDataBitsSize = finalDataSize * 8;

			this->m_MessageBlock[this->m_MessageAddPosition] = 0x80;

			memset (&this->m_MessageBlock[this->m_MessageAddPosition + 1], 0, 64 - (this->m_MessageAddPosition + 1));

			//0x80をセットした位置が448ビット目(56バイト目) 
			//以上であればハッシュブロックを実行する
			if (this->m_MessageAddPosition >= 56) {
				this->BlockProcess ();
				memset (this->m_MessageBlock, 0, 56);
			}

			for (size_t i = 0; i < 8; i++) {
				this->m_MessageBlock[63 - i] = (finalDataBitsSize >> (8 * i)) & 0xFF;
			}

			this->BlockProcess ();

			this->State = EComputeState::Finalized;

			return true;
		}
	};

	template <typename HashValueType> class CSHABase64BitUnit : public  CSHABase<128, uint64_t, HashValueType> {
	public:

		virtual bool Finalize (void) {
			if (this->State != EComputeState::Updatable) return false;

			uint64_t finalDataSize = this->m_AllMessageSize + this->m_MessageAddPosition;
			uint64_t finalDataBitsSize = finalDataSize * 8;

			this->m_MessageBlock[this->m_MessageAddPosition] = 0x80;

			memset (&this->m_MessageBlock[this->m_MessageAddPosition + 1], 0, 128 - (this->m_MessageAddPosition + 1));

			//0x80をセットした位置が896ビット目(112バイト目) 
			//以上であればハッシュブロックを実行する
			if (this->m_MessageAddPosition >= 112) {
				uint32_t targetSize = this->m_MessageAddPosition;
				this->BlockProcess ();
				memset (this->m_MessageBlock, 0, targetSize);
			}

			for (size_t i = 0; i < 8; i++) {
				this->m_MessageBlock[127 - i] = (finalDataBitsSize >> (8 * i)) & 0xFF;
			}

			this->BlockProcess ();

			this->State = EComputeState::Finalized;
			return true;
		}
	};
}

namespace Functions {
	template <typename T> T LeftRotate (T   value, uint32_t numberOfRotateBits) {
		uint32_t  typeBits = sizeof (T) * 8;
		uint32_t realRotateBits = numberOfRotateBits % typeBits;
		return (value << realRotateBits) | (value >> (typeBits - realRotateBits));
	}

	template <typename T> T RightRotate (T   value, uint32_t numberOfRotateBits) {
		uint32_t  typeBits = sizeof (T) * 8;
		uint32_t realRotateBits = numberOfRotateBits % typeBits;
		return (value >> realRotateBits) | (value << (typeBits - realRotateBits));
	}
}

END_HSHASH_NAMESPACE