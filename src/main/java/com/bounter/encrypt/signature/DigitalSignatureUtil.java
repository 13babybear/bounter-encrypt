package com.bounter.encrypt.signature;

import com.bounter.encrypt.encode.EncodeUtil;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by simon on 2017/6/21.
 * 数字签名工具类
 */
public class DigitalSignatureUtil {

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
     * 获取十六进制的MD5WithRSA签名
     * @param privateKeyHex
     * @param data
     * @return
     * @throws Exception
     */
    public static String signMD5WithRSAHex(String privateKeyHex, byte[] data) throws Exception {
        //根据十六进制私钥串生成私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(EncodeUtil.decodeHex(privateKeyHex));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //私钥签名
        Signature signature = Signature.getInstance("MD5WithRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return EncodeUtil.encodeHex(signature.sign());
    }

    /**
     * 验证MD5WithRSA签名
     * @param publicKeyHex
     * @param signHex
     * @param data
     * @return
     * @throws Exception
     */
    public static boolean verifyMD5WithRSAHex(String publicKeyHex, String signHex, byte[] data) throws Exception {
        //根据十六进制公钥串生成公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(EncodeUtil.decodeHex(publicKeyHex));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        //公钥验证
        Signature signature = Signature.getInstance("MD5WithRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(EncodeUtil.decodeHex(signHex));
    }


    public static void main(String[] args) throws Exception {
        String dataStr = "小苏苏";
        Map<String,String> keyMap = genRSAHexKeyMap();
        String signHex = signMD5WithRSAHex(keyMap.get("private").toString(),dataStr.getBytes());
        System.out.println(signHex);
        boolean verifyResult = verifyMD5WithRSAHex(keyMap.get("public").toString(),signHex,dataStr.getBytes());
        System.out.println(verifyResult);
    }
}
