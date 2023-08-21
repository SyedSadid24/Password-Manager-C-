#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <iostream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/md5.h>
#include <cryptopp/pwdbased.h>

using namespace std;
using namespace CryptoPP;

string md5gen(string passwd);

string encrypt(string passwd, string passgen) {

    string part1 = "cd7fe79306f6c441078e5f71687a3c01";
    string genkey = passwd + part1;
    string finalkey = md5gen(genkey);
    string ciphertext;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0x00, (byte*)finalkey.c_str(), finalkey.size(), iv.BytePtr(), iv.size(), 1000);

    AES::Encryption aesEncryption(key, key.size());
    CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(passgen.c_str()), passgen.length());
    stfEncryptor.MessageEnd();

    return ciphertext;

}

string decrypt(string passwd, string passdcrpt) {

    string part1 = "cd7fe79306f6c441078e5f71687a3c01";
    string genkey = passwd + part1;
    string finalkey = md5gen(genkey);
    string decryptedtext;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0x00, (byte*)finalkey.c_str(), finalkey.size(), iv.BytePtr(), iv.size(), 1000);

    AES::Decryption aesDecryption(key, key.size());
    CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    StreamTransformationFilter stfDecryptor(cbcDecryption, new StringSink(decryptedtext));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(passdcrpt.c_str()), passdcrpt.length());
    stfDecryptor.MessageEnd();

    return decryptedtext;
}

string md5gen(string passwd) {
    string hash;

    Weak1::MD5 md5;
    StringSource(passwd, true,
        new HashFilter(md5,
            new HexEncoder(
                new StringSink(hash)
            )
        )
    );

    return hash;
}