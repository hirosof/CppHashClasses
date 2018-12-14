#include <stdio.h>
#include "HSSHA1.hpp"
#include "HSSHA2.hpp"
#include "HSHMAC.hpp"
void ShowStringHash (const char *pString);


void Test (void);


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


void HMACCodeTest (void);


int main (void) {
	using namespace hirosof::Hash;
	using namespace hirosof::Hash::HMAC;

	
	char keystr[] = "KeyString";
	char msg[] = "MessageData";

	CHMACKeySHA1Builder hmacKeyBuilder;
	hmacKeyBuilder.Compute (keystr);

	CHMACSHA1  hmacsha1 (hmacKeyBuilder);
	hmacsha1.Compute (msg);

	CSHA1Value value;
	hmacsha1.GetHash (&value);
	printf ("キー : %s\nメッセージ : %s\n", keystr, msg);
	printf ("HMAC-SHA1 : ");
	ShowHash (value);

	return 0;
}
void Test (void) {
	ShowStringHash ("");
	ShowStringHash ("abcdefghijklmnopqrstuvwxyz");
	ShowStringHash ("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	ShowStringHash ("0123456789");
	ShowStringHash ("Test");
	ShowStringHash ("Example");
	ShowStringHash ("Sample");
	printf ("\n");
	ShowStringHash ("テスト");
	ShowStringHash ("サンプル");
	ShowStringHash ("データ");
	ShowStringHash ("テストデータ");
	ShowStringHash ("サンプルデータ");
	ShowStringHash ("あいうえお");
	ShowStringHash ("アイウエオ");
}

void ShowStringHash (const char *pString) {
	using namespace hirosof::Hash;

	printf ("<<対象の文字列：%s>>\n", pString);

	CSHA1 sha1;
	CSHA1Value value1;
	sha1.Update (pString);
	sha1.Finalize ();
	sha1.GetHash (&value1);
	printf ("      SHA1 : %s\n", value1.ToString ().c_str ());

	CSHA224  sha224;
	CSHA224Value value224;
	sha224.Update (pString);
	sha224.Finalize ();
	sha224.GetHash (&value224);
	printf ("    SHA224 : %s\n", value224.ToString ().c_str ());

	CSHA256  sha256;
	CSHA256Value value256;
	sha256.Update (pString);
	sha256.Finalize ();
	sha256.GetHash (&value256);
	printf ("    SHA256 : %s\n", value256.ToString ().c_str ());

	CSHA384 sha384;
	CSHA384Value value384;
	sha384.Update (pString);
	sha384.Finalize ();
	sha384.GetHash (&value384);
	printf ("    SHA384 : %s\n", value384.ToString ().c_str ());

	CSHA512 sha512;
	CSHA512Value value512;
	sha512.Update (pString);
	sha512.Finalize ();
	sha512.GetHash (&value512);
	printf ("    SHA512 : %s\n", value512.ToString ().c_str ());

	CSHA512Per224 sha512Per224;
	CSHA512Per224Value value512Per224;
	sha512Per224.Update (pString);
	sha512Per224.Finalize ();
	sha512Per224.GetHash (&value512Per224);
	printf ("SHA512/224 : %s\n", value512Per224.ToString ().c_str ());


	CSHA512Per256 sha512Per256;
	CSHA512Per256Value value512Per256;
	sha512Per256.Update (pString);
	sha512Per256.Finalize ();
	sha512Per256.GetHash (&value512Per256);
	printf ("SHA512/256 : %s\n", value512Per256.ToString ().c_str ());

	printf ("\n");
}


void HMACCodeTest (void) {

	using namespace hirosof::Hash;


	char key[] = "key";
	size_t key_len = strlen (key);
	char data[] = "data";

	if (key_len > 64) return;

	ShowStringHash (data);

	printf ("HMAC-SHA1の実験\n");

	uint8_t k0[64];

	memcpy (k0, key, key_len);
	memset (k0 + key_len, 0, 64 - key_len);

	CSHA1 isha1;

	for (size_t i = 0; i < 64; i++)
	{
		uint8_t c = k0[i] ^ 0x36;
		isha1.Update (&c, 1);
	}

	isha1.Update (data);
	isha1.Finalize ();

	CSHA1 osha1;
	for (size_t i = 0; i < 64; i++)
	{
		uint8_t c = k0[i] ^ 0x5c;
		osha1.Update (&c, 1);
	}


	CSHA1Value ival;
	isha1.GetHash (&ival);


	for (size_t i = 0; i < ival.Count(); i++)
	{
		uint8_t c = ival[i];
		osha1.Update (&c, 1);
	}


	osha1.Finalize ();


	ShowHash (osha1);

}
