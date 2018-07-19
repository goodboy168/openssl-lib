#include <openssl/des.h>
#include <openssl/rand.h>
#include <iostream>
#include <string>
#include "Str.h"
#include "ErrCode.h"
#include "string.h"
#include "stdio.h"
#include "stdlib.h"
#include "DES.h"

using namespace std;

const string DESKEY = "1234567890ABCDEFFEDCBA0987654321";

/*
随机产生DES/3DES密钥
keyLen 8:单倍 16:双倍 24:三倍
返回值：
>0 正确 密钥长度
<=0 错误 相应的错误码
*/
int RandomDesKey(const int keyLen, string& desKey)
{
	char key[24];
	DES_cblock randKey;
	int len = 0, x = 0, ret = 0;

	if (keyLen != 8 && keyLen != 16 && keyLen != 24)
		return errCodeOffsetOfCommon_CodeParameter;

	memset(key, 0, sizeof(key));
	for (x=0;x<keyLen;x+=8)
	{
		ret = DES_random_key(&randKey);
		if (ret == 0)
		{
			return errCodeOffsetOfCert_Arithmetic;
		}
		memcpy(key+x, randKey, 8);
		len += 8;
	}

	string keyBuf(key, len);
	desKey = keyBuf;
	return len;
}

/*
使用DES算法对数据加密
desKey	密钥，支持单倍、双倍、三倍
data	源数据 长度必须为8的倍数
mode 	加密模式 ECB CBC CFB
iv	仅 CBC CFB两种模式才有此值,长度为8字节
返回值：
>=0 加密数据的长度
<0 错误码
*/
int DesEncryptData(const string &desKey, const string &data, int mode, const string &iv, string &encData)
{
	int keyLen = 0, x = 0;
	long dataLen = 0;
	DES_key_schedule ks1, ks2, ks3;
	unsigned char tmpData[8], ke1[8], ke2[8], ke3[8], ivec[8];
	unsigned char input[8192], output[8192];

	keyLen = desKey.length();
	dataLen = data.length();

	if (keyLen == 0 || dataLen == 0)
		return errCodeOffsetOfCommon_CodeParameter;

	memset(input, 0, 8192);
	memset(output, 0, 8192);
	memcpy(input, data.c_str(), dataLen);
	
	switch (keyLen)
	{
		case 8:
			memset(ke1, 0, 8);  
			memcpy(ke1, desKey.c_str(), 8);
			DES_set_key_unchecked((const_DES_cblock*)ke1, &ks1);  

			switch (mode)
			{
				case CBC:
					memcpy(ivec, iv.c_str(), 8);
					DES_cbc_encrypt(input, output, dataLen, &ks1, (DES_cblock *)ivec, DES_ENCRYPT);
					break;
				case CFB:
					memcpy(ivec, iv.c_str(), 8);
					DES_cfb_encrypt(input, output, 8, dataLen, &ks1, (DES_cblock *)ivec, DES_ENCRYPT);
					break;
				case ECB:
				default:
					for (x=0;x<dataLen;x+=8)
					{
						memcpy(tmpData, input+x, 8); 
						DES_ecb_encrypt((const_DES_cblock*)tmpData, (DES_cblock *)(output+x), &ks1, DES_ENCRYPT);
					}
					break;
			}
			break;

		case 16:
		case 24:
			memset(ke1, 0, 8);  
			memset(ke2, 0, 8);  
			memset(ke3, 0, 8); 

			if (keyLen == 16)
			{
				memcpy(ke1, desKey.c_str(), 8);
				memcpy(ke2, desKey.c_str()+8, 8);
				memcpy(ke3, desKey.c_str(), 8);
			}else
			{
				memcpy(ke1, desKey.c_str(), 8);
				memcpy(ke2, desKey.c_str()+8, 8);
				memcpy(ke3, desKey.c_str()+16, 8);
			}

			DES_set_key_unchecked((const_DES_cblock*)ke1, &ks1);  
			DES_set_key_unchecked((const_DES_cblock*)ke2, &ks2);  
			DES_set_key_unchecked((const_DES_cblock*)ke3, &ks3);  

			switch (mode)
			{
				case CBC:
					memcpy(ivec, iv.c_str(), 8);
					DES_ede3_cbc_encrypt(input, output, dataLen, &ks1, &ks2, &ks3, (DES_cblock *)ivec, DES_ENCRYPT);
					break;
				case CFB:
					memcpy(ivec, iv.c_str(), 8);
					DES_ede3_cfb_encrypt(input, output, 8, dataLen, &ks1, &ks2, &ks3, (DES_cblock *)ivec, DES_ENCRYPT);
				case ECB:
				default:
					for (x=0;x<dataLen;x+=8)
					{
						memcpy(tmpData, input+x, 8); 
						DES_ecb3_encrypt((const_DES_cblock*)tmpData, (DES_cblock *)(output+x), &ks1, &ks2, &ks3, DES_ENCRYPT);
					}
					break;
			}
			break;

		default:
			dataLen = errCodeOffsetOfCommon_CodeParameter;
			break;
	}

	if (dataLen > 0)
	{
		string result((char *)output, dataLen);
		encData = result;
	}

	return dataLen;
}

/*
使用DES算法对数据解密
desKey	密钥，支持单倍、双倍、三倍
data	源数据 长度必须为8的倍数
mode 	加密模式 ECB CBC CFB
iv	仅CBC CFB两种模式才有此值
*/
int DesDecryptData(const string &desKey, const string &data, int mode, const string &iv, string &plainData)
{
	int keyLen = 0, x = 0;
	long dataLen = 0;
	DES_key_schedule ks1, ks2, ks3;
	unsigned char tmpData[8], ke1[8], ke2[8], ke3[8], ivec[8];  
	unsigned char input[8192], output[8192];

	keyLen = desKey.length();
	dataLen = data.length();

	if (keyLen == 0 || dataLen == 0)
		return errCodeOffsetOfCommon_CodeParameter;

	memset(input, 0, 8192);
	memset(output, 0, 8192);
	memcpy(input, data.c_str(), dataLen);
	
	switch (keyLen)
	{
		case 8:
			memset(ke1, 0, 8);  
			memcpy(ke1, desKey.c_str(), 8);
			DES_set_key_unchecked((const_DES_cblock*)ke1, &ks1);  

			switch (mode)
			{
				case CBC:
					memcpy(ivec, iv.c_str(), 8);
					DES_cbc_encrypt(input, output, dataLen, &ks1, (DES_cblock *)ivec, DES_DECRYPT);
					break;
				case CFB:
					memcpy(ivec, iv.c_str(), 8);
					DES_cfb_encrypt(input, output, 8, dataLen, &ks1, (DES_cblock *)ivec, DES_DECRYPT);
					break;
				case ECB:
				default:
					for (x=0;x<dataLen;x+=8)
					{
						memcpy(tmpData, input+x, 8); 
						DES_ecb_encrypt((const_DES_cblock*)tmpData, (DES_cblock *)(output+x), &ks1, DES_DECRYPT);
					}
					break;
			}
			break;

		case 16:
		case 24:
			memset(ke1, 0, 8);  
			memset(ke2, 0, 8);  
			memset(ke3, 0, 8); 

			if (keyLen == 16)
			{
				memcpy(ke1, desKey.c_str(), 8);
				memcpy(ke2, desKey.c_str()+8, 8);
				memcpy(ke3, desKey.c_str(), 8);
			}else
			{
				memcpy(ke1, desKey.c_str(), 8);
				memcpy(ke2, desKey.c_str()+8, 8);
				memcpy(ke3, desKey.c_str()+16, 8);
			}

			DES_set_key_unchecked((const_DES_cblock*)ke1, &ks1);  
			DES_set_key_unchecked((const_DES_cblock*)ke2, &ks2);  
			DES_set_key_unchecked((const_DES_cblock*)ke3, &ks3);  

			switch (mode)
			{
				case CBC:
					memcpy(ivec, iv.c_str(), 8);
					DES_ede3_cbc_encrypt(input, output, dataLen, &ks1, &ks2, &ks3, (DES_cblock *)ivec, DES_DECRYPT);
					break;
				case CFB:
					memcpy(ivec, iv.c_str(), 8);
					DES_ede3_cfb_encrypt(input, output, 8, dataLen, &ks1, &ks2, &ks3, (DES_cblock *)ivec, DES_DECRYPT);
				case ECB:
				default:
					for (x=0;x<dataLen;x+=8)
					{
						memcpy(tmpData, input+x, 8); 
						DES_ecb3_encrypt((const_DES_cblock*)tmpData, (DES_cblock *)(output+x), &ks1, &ks2, &ks3, DES_DECRYPT);
					}
					break;
			}
			break;

		default:
			dataLen = errCodeOffsetOfCommon_CodeParameter;
			break;
	}

	if (dataLen > 0)
	{
		string result((char *)output, dataLen);
		plainData = result;
	}
	return dataLen;
}

//使用默认密钥进行加密
int DesEncryptDataUseDefaultKey(const string &data, string &encData)
{
	char keyBuf[48], desKey[24];
	memcpy(keyBuf, DESKEY.c_str(), 32);
	int len = aschex_to_bcdhex(keyBuf, 32, desKey);
	desKey[16] = '\0';
	string strDesKey(desKey, len);
	return(DesEncryptData(strDesKey, data, ECB, "", encData));
}

//使用默认密钥进行解密 
int DesDecryptDataUseDefaultKey(const string &data, string &plainData)
{
	char keyBuf[48], desKey[24];
	memcpy(keyBuf, DESKEY.c_str(), 32);
	int len = aschex_to_bcdhex(keyBuf, 32, desKey);
	desKey[16] = '\0';
	string strDesKey(desKey, len);
	return(DesDecryptData(strDesKey, data, ECB, "", plainData));
}
