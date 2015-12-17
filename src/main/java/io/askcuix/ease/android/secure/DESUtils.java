package io.askcuix.ease.android.secure;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * 3DES加密工具类。
 * <p/>
 * 用于解决Java，Android和iOS三个平台加解密不一致的问题。
 * <p/>
 * 该工具类与Java平台共用。
 * <p/>
 * Created by Chris on 15/12/17.
 */
public class DESUtils {

    // 向量
    private final static String iv = "01234567";
    // 加解密统一使用的编码方式
    private final static String DEFAULT_ENCODING = "UTF-8";

    private static final String KEY_ALGORITHM = "desede";

    private static final String DEFAULT_CIPHER_ALGORITHM = "desede/CBC/PKCS5Padding";

    /**
     * 3DES加密
     *
     * @param plainText 普通文本
     * @return
     * @throws Exception
     */
    public static String encode(String plainText, String secretKey) {
        try {
            Key deskey = null;
            DESedeKeySpec spec = new DESedeKeySpec(secretKey.getBytes(DEFAULT_ENCODING));
            SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
            deskey = keyfactory.generateSecret(spec);

            Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
            IvParameterSpec ips = new IvParameterSpec(iv.getBytes(DEFAULT_ENCODING));
            cipher.init(Cipher.ENCRYPT_MODE, deskey, ips);
            byte[] encryptData = cipher.doFinal(plainText.getBytes(DEFAULT_ENCODING));
            return Base64.encode(encryptData);
        } catch (Exception e) {
            throw new IllegalStateException("[encode] plainText: " + plainText + ", secretKey: " + secretKey + ", error: " + e.getMessage());
        }
    }

    /**
     * 3DES解密
     *
     * @param encryptText 加密文本
     * @return
     * @throws Exception
     */
    public static String decode(String encryptText, String secretKey) {
        try {
            Key deskey = null;
            DESedeKeySpec spec = new DESedeKeySpec(secretKey.getBytes(DEFAULT_ENCODING));
            SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
            deskey = keyfactory.generateSecret(spec);
            Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
            IvParameterSpec ips = new IvParameterSpec(iv.getBytes(DEFAULT_ENCODING));
            cipher.init(Cipher.DECRYPT_MODE, deskey, ips);

            byte[] decryptData = cipher.doFinal(Base64.decode(encryptText));
            return new String(decryptData, DEFAULT_ENCODING);
        } catch (Exception e) {
            throw new IllegalStateException("[decode] encryptText: " + encryptText + ", secretKey: " + secretKey + ", error: " + e.getMessage());
        }
    }
}
