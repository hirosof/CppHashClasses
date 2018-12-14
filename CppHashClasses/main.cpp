#include <stdio.h>
#include "HSSHA1.hpp"
#include "HSSHA2.hpp"

void ShowStringHash (const char *pString);


void Test (void);


template <typename T> void ShowHash (const hirosof::Hash::Base::CHashBase<T>  &hash) {
	T value;

	if (hash.GetHash (&value)) {
		printf ("%s\n", value.ToString ().c_str ());
	}	
}



void HMACCodeTest (void);


int main (void) {
	using namespace hirosof::Hash;

	HMACCodeTest ();




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
	sha1.UpdateString (pString);
	sha1.Finalize ();
	sha1.GetHash (&value1);
	printf ("      SHA1 : %s\n", value1.ToString ().c_str ());

	CSHA224  sha224;
	CSHA224Value value224;
	sha224.UpdateString (pString);
	sha224.Finalize ();
	sha224.GetHash (&value224);
	printf ("    SHA224 : %s\n", value224.ToString ().c_str ());

	CSHA256  sha256;
	CSHA256Value value256;
	sha256.UpdateString (pString);
	sha256.Finalize ();
	sha256.GetHash (&value256);
	printf ("    SHA256 : %s\n", value256.ToString ().c_str ());

	CSHA384 sha384;
	CSHA384Value value384;
	sha384.UpdateString (pString);
	sha384.Finalize ();
	sha384.GetHash (&value384);
	printf ("    SHA384 : %s\n", value384.ToString ().c_str ());

	CSHA512 sha512;
	CSHA512Value value512;
	sha512.UpdateString (pString);
	sha512.Finalize ();
	sha512.GetHash (&value512);
	printf ("    SHA512 : %s\n", value512.ToString ().c_str ());

	CSHA512Per224 sha512Per224;
	CSHA512Per224Value value512Per224;
	sha512Per224.UpdateString (pString);
	sha512Per224.Finalize ();
	sha512Per224.GetHash (&value512Per224);
	printf ("SHA512/224 : %s\n", value512Per224.ToString ().c_str ());


	CSHA512Per256 sha512Per256;
	CSHA512Per256Value value512Per256;
	sha512Per256.UpdateString (pString);
	sha512Per256.Finalize ();
	sha512Per256.GetHash (&value512Per256);
	printf ("SHA512/256 : %s\n", value512Per256.ToString ().c_str ());

	printf ("\n");
}


void HMACCodeTest (void) {

	using namespace hirosof::Hash;


	char key[] = "key";
	char data[] = "data";


	ShowStringHash (data);

	printf ("HMAC-SHA1の実験\n");





 	

}
