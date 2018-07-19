#include <string>
#include <iostream>

#ifndef Des_H_
#define Des_H_

#define ECB 1
#define CBC 2
#define CFB 3

/*
随机产生DES/3DES密钥
keyLen 8:单倍 16:双倍 24:三倍
返回值：
>0 正确 密钥长度
<=0 错误 相应的错误码
*/
int RandomDesKey(int keyLen, std::string& desKey);

/*
使用DES算法对数据加密
desKey  密钥，支持单倍、双倍、三倍
data    源数据 长度必须为8的倍数
mode    加密模式 ECB CBC CFB
iv      仅 CBC CFB两种模式才有此值
*/
int DesEncryptData(const std::string &desKey, const std::string &data, int mode, const std::string &iv, std::string &encData);

/*
使用DES算法对数据解密
desKey  密钥，支持单倍、双倍、三倍
data    源数据 长度必须为8的倍数
mode    加密模式 ECB CBC CFB
iv      仅CBC CFB两种模式才有此值
*/
int DesDecryptData(const std::string &desKey, const std::string &data, int mode, const std::string &iv, std::string &plainData);

//使用默认密钥进行加密
int DesEncryptDataUseDefaultKey(const std::string &data, std::string &encData);

//使用默认密钥进行解密 
int DesDecryptDataUseDefaultKey(const std::string &data, std::string &plainData);

#endif
