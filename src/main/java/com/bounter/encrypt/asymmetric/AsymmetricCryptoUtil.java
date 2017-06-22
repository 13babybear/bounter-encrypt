package com.bounter.encrypt.asymmetric;

import com.bounter.encrypt.encode.EncodeUtil;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by simon on 2017/6/20.
 * 非对称加密工具类，封装一些常用的非对称加密算法实现
 */
public class AsymmetricCryptoUtil {

    /**
     * 生成1024位十六进制形式的RSA密钥对，公钥："public",私钥："private"
     * @return
     * @throws Exception
     */
    public static Map<String,String> genRSAHexKeyMap() throws Exception {
        //创建密钥对容器
        Map<String,String> keyMap = new HashMap<>();
        //生成公钥、私钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
        keyMap.put("public", EncodeUtil.encodeHex(((Key)rsaPublicKey).getEncoded()));
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        keyMap.put("private", EncodeUtil.encodeHex(((Key)rsaPrivateKey).getEncoded()));
        return keyMap;
    }

    /**
     * RSA公钥加密
     * @param publicKeyHex
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] encryptRSAByPublic(String publicKeyHex, byte[] data) throws Exception {
        //根据十六进制公钥串生成公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(EncodeUtil.decodeHex(publicKeyHex));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        //公钥加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        return cipher.doFinal(data);
    }

    /**
     * RSA私钥加密
     * @param privateKeyHex
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] encryptRSAByPrivate(String privateKeyHex, byte[] data) throws Exception {
        //根据十六进制私钥串生成私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(EncodeUtil.decodeHex(privateKeyHex));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //私钥加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE,privateKey);
        return cipher.doFinal(data);
    }

    /**
     * RSA公钥解密
     * @param publicKeyHex
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] decryptRSAByPublic(String publicKeyHex, byte[] data) throws Exception {
        //根据十六进制公钥串生成公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(EncodeUtil.decodeHex(publicKeyHex));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        //公钥解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE,publicKey);
        return cipher.doFinal(data);
    }

    /**
     * RSA私钥解密
     * @param privateKeyHex
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] decryptRSAByPrivate(String privateKeyHex, byte[] data) throws Exception {
        //根据十六进制私钥串生成私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(EncodeUtil.decodeHex(privateKeyHex));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //私钥解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        return cipher.doFinal(data);
    }


    public static void main(String[] args) throws Exception {
        String dataStr = "小苏苏";
        Map<String,String> keyMap = genRSAHexKeyMap();
        byte[] encryptData = encryptRSAByPublic(keyMap.get("public").toString(),dataStr.getBytes());
        byte[] decryptData = decryptRSAByPrivate(keyMap.get("private").toString(),encryptData);
        System.out.println(new String(decryptData));
        encryptData = encryptRSAByPrivate(keyMap.get("private").toString(),dataStr.getBytes());
        decryptData = decryptRSAByPublic(keyMap.get("public").toString(),encryptData);
        System.out.println(new String(decryptData));
    }
}
