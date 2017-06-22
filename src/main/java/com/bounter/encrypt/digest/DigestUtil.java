package com.bounter.encrypt.digest;

import org.apache.commons.codec.digest.DigestUtils;

/**
 * Created by simon on 2017/6/19.
 * 消息摘要工具类，封装一些常见的消息摘要算法实现
 */
public class DigestUtil {

    /**
     * commons codec实现md5加密，返回加密后的十六进制字符串
     * @param data
     * @return
     */
    public static String md5Hex(String data) {
        return DigestUtils.md5Hex(data);
    }

    /**
     * commons codec实现sha1加密，返回加密后的十六进制字符串
     * @param data
     * @return
     */
    public static String sha1Hex(String data) {
        return DigestUtils.sha1Hex(data);
    }

    /**
     * commons codec实现sha256加密，返回加密后的十六进制字符串
     * @param data
     * @return
     */
    public static String sha256Hex(String data) {
        return DigestUtils.sha256Hex(data);
    }
}
