#include <stdio.h>
#include "HSHMAC.hpp"

template <typename T> void ShowHash (const hirosof::Hash::Base::CHashBase<T>  &hash) {
	T value;
	if (hash.GetHash (&value)) {
		printf ("%s\n", value.ToString ().c_str ());
	} else {
		printf ("err\n");
	}
}

template <typename T> void ShowHash (const hirosof::Hash::Base::CHashValueBaseAbstruct<T> &hashv) {
	printf ("%s\n", hashv.ToString ().c_str ());
}

template<typename hash> void PrintHMACHash (const char *beforetext , const char *key, const char *msg) {
	using namespace hirosof::Hash;
	using namespace hirosof::Hash::HMAC;	

	CHMAC<hash>  hmac (key);
	hmac.Compute (msg);

	if (beforetext) printf ("%s : ", beforetext);
	ShowHash (hmac);
}

template<typename hash> void PrintHash (const char *beforetext, const char *msg) {
	using namespace hirosof::Hash;
	hash hash_algo;
	hash_algo.Compute (msg);
	if (beforetext) printf ("%s : ", beforetext);
	ShowHash (hash_algo);
}

bool NormalHashTest (const char *pmsg);
bool HMACHashTest (const char *pkey,const char *pmsg , bool withShowNormalHashFlag = true);

int main (void) {

	using namespace hirosof::Hash;
	using namespace hirosof::Hash::HMAC;
	HMACHashTest ("key", "data",true);
	return 0;
}

bool NormalHashTest (const char *pmsg) {
	using namespace hirosof::Hash;

	if (pmsg == nullptr) return false;

	printf ("<<Normal Hash>>\n");
	printf ("メッセージ : %s\n", pmsg);
	PrintHash<CMD5> ("       MD5", pmsg);
	PrintHash<CSHA1> ("      SHA1", pmsg);
	PrintHash<CSHA224> ("    SHA224", pmsg);
	PrintHash<CSHA256> ("    SHA256", pmsg);
	PrintHash<CSHA384> ("    SHA384", pmsg);
	PrintHash<CSHA512> ("    SHA512", pmsg);
	PrintHash<CSHA512Per224> ("SHA512/224", pmsg);
	PrintHash<CSHA512Per256> ("SHA512/256", pmsg);
	printf ("\n");
	return true;
}

bool HMACHashTest (const char *pkey, const char *pmsg, bool withShowNormalHashFlag){
	using namespace hirosof::Hash;
	using namespace hirosof::Hash::HMAC;

	if (pkey == nullptr) return false;
	if (pmsg == nullptr) return false;

	if (withShowNormalHashFlag) {
		NormalHashTest (pkey);
		NormalHashTest (pmsg);
	}

	printf ("<<HMAC>>\n");
	printf ("           キー : %s\n     メッセージ : %s\n", pkey, pmsg);
	PrintHMACHash<CMD5> ("       HMAC-MD5", pkey, pmsg);
	PrintHMACHash<CSHA1> ("      HMAC-SHA1", pkey, pmsg);
	PrintHMACHash<CSHA224> ("    HMAC-SHA224", pkey, pmsg);
	PrintHMACHash<CSHA256> ("    HMAC-SHA256", pkey, pmsg);
	PrintHMACHash<CSHA384> ("    HMAC-SHA384", pkey, pmsg);
	PrintHMACHash<CSHA512> ("    HMAC-SHA512", pkey, pmsg);
	PrintHMACHash<CSHA512Per224> ("HMAC-SHA512/224", pkey, pmsg);
	PrintHMACHash<CSHA512Per256> ("HMAC-SHA512/256", pkey, pmsg);
	printf ("\n");

	return true;
}
