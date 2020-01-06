package org.shiro.auth.common.utils;


import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.Security;

/**
 * 加密工具类
 */
@Slf4j
public class EncryptUtils {

    private static final String ALGORITH_NAME = "md5";
    private static final int HASH_ITERATIONS = 2;

    //设置默认密匙
    private static String strDefaultKey = "defaultKey";
    //加密
    private Cipher encryptCipher = null;
    //解密
    private Cipher decryptCipher = null;

    public EncryptUtils() {
        this(strDefaultKey);
    }

    private EncryptUtils(String strKey) {
        try{
            Security.addProvider(new com.sun.crypto.provider.SunJCE());
            Key key = getKey(strKey.getBytes());

            encryptCipher = Cipher.getInstance("DES");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key);

            decryptCipher = Cipher.getInstance("DES");
            decryptCipher.init(Cipher.DECRYPT_MODE, key);
        }catch (Exception e){
            log.error("error：{}", e.getMessage());
        }
    }

    public String encrypt(String strIn) {
        try {
            return byteArr2HexStr(encrypt(strIn.getBytes()));
        } catch (Exception e) {
            return "";
        }
    }

    public String decrypt(String strIn) {
        try {
            return new String(decrypt(hexStr2ByteArr(strIn)));
        } catch (Exception e) {
            return "";
        }
    }

    private static String byteArr2HexStr(byte[] arrB) {
        int iLen = arrB.length;
        StringBuilder sb = new StringBuilder(iLen * 2);
        for (byte anArrB : arrB) {
            int intTmp = anArrB;
            while (intTmp < 0) {
                intTmp = intTmp + 256;
            }
            if (intTmp < 16) {
                sb.append("0");
            }
            sb.append(Integer.toString(intTmp, 16));
        }
        return sb.toString();
    }

    private static byte[] hexStr2ByteArr(String strIn) {
        byte[] arrB = strIn.getBytes();
        int iLen = arrB.length;

        byte[] arrOut = new byte[iLen / 2];
        for (int i = 0; i < iLen; i = i + 2) {
            String strTmp = new String(arrB, i, 2);
            arrOut[i / 2] = (byte) Integer.parseInt(strTmp, 16);
        }
        return arrOut;
    }

    private byte[] encrypt(byte[] arrB) throws Exception {
        return encryptCipher.doFinal(arrB);
    }

    private byte[] decrypt(byte[] arrB) throws Exception {
        return decryptCipher.doFinal(arrB);
    }

    private Key getKey(byte[] arrBTmp) {
        byte[] arrB = new byte[8];
        for (int i = 0; i < arrBTmp.length && i < arrB.length; i++) {
            arrB[i] = arrBTmp[i];
        }
        return new javax.crypto.spec.SecretKeySpec(arrB, "DES");
    }

    public static String MD5Encrypt(String password) {
        return new SimpleHash(ALGORITH_NAME, password, ByteSource.Util.bytes(password), HASH_ITERATIONS).toHex();
    }

    public static String MD5Encrypt(String username, String password) {
        return new SimpleHash(ALGORITH_NAME, password, ByteSource.Util.bytes(username.toLowerCase() + password), HASH_ITERATIONS).toHex();
    }
}
