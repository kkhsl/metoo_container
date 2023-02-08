package com.metoo.nspm.core.utils;

import com.alibaba.fastjson.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

@Component
public class AesEncryptUtils {

    //可配置到Constant中，并读取配置文件注入,16位,自己定义
    private static final String KEY = "@NPzwDvPmCJvpYuE";

    //参数分别代表 算法名称/加密模式/数据填充方式
    private static final String ALGORITHMSTR = "AES/ECB/PKCS5Padding";

    /**
     * 加密
     * @param content 加密的字符串
     * @param encryptKey key值
     * @return
     * @throws Exception
     */
    public static String encrypt(String content, String encryptKey) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        Cipher cipher = Cipher.getInstance(ALGORITHMSTR);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptKey.getBytes(), "AES"));
        byte[] b = cipher.doFinal(content.getBytes("UTF-8"));
        // 采用base64算法进行转码,避免出现中文乱码
        return Base64.encodeBase64String(b);

    }

    /**
     * 解密
     * @param encryptStr 解密的字符串
     * @param decryptKey 解密的key值
     * @return
     * @throws Exception
     */
    public static String decrypt(String encryptStr, String decryptKey) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        Cipher cipher = Cipher.getInstance(ALGORITHMSTR);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptKey.getBytes(), "AES"));
        // 采用base64算法进行转码,避免出现中文乱码
        byte[] encryptBytes = Base64.decodeBase64(encryptStr.getBytes("UTF-8"));
        byte[] decryptBytes = cipher.doFinal(encryptBytes);
        return new String(decryptBytes);
    }

    public String encrypt(String content) throws Exception {
        return encrypt(content, KEY);
    }
    public String decrypt(String encryptStr) throws Exception {
        return decrypt(encryptStr, KEY);
    }

    @Test
    public void test(){
        String sn = "Rd5w73WqxikC8EjynsCzzA==";
        String decrypt = null;
        try {
            decrypt = decrypt(sn, KEY);
            System.out.println("解密后：" + decrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) throws Exception {
        Map map=new HashMap<String,String>();
        map.put("expireTime","1680004102");
        map.put("systemSN","9V1ZLW2");

        String content = JSONObject.toJSONString(map);
        System.out.println("加密前：" + content);

        String encrypt = encrypt(content, KEY);
        System.out.println("加密后：" + encrypt);

        String decrypt = decrypt("iqiRfaK2eZiaxwhfNvJ4qbGrAMTEhC+rXJw84y2rPPG8QtpK0BChvDfx3azZ70Rj1dvzKxP9tWsZSOCIpNQtVtj/M0uhMn29NCSgUfbCvOBLmfBVHxWJxOUqKzMEM5iNfeqSx4brhPYa+W4xbYWV9rsseWPLqfnj/FGmrBCZVN4TQ/WJMFSHN/gn2wIguTgHJJkIUkqVoujwF7vInnjoPsfzDQmOCjZD6xokfRTn8JsRtJB98qT9H1b3aThf6TAF+daj1ixdOa5TkpkCzpLRvw==", KEY);
        System.out.println("解密后：" + decrypt);

    }


//    public static void main(String[] args) {
//        // 比较时间戳
//        String endTimeStamp = "1647936175";
//        Calendar calendar = Calendar.getInstance();
//        calendar.setTime(new Date());
//        long currentTime = calendar.getTimeInMillis();
//        long timeStampSec = currentTime / 1000;// 13位时间戳（单位毫秒）转换为10位字符串（单位秒）
//        String timestamp = String.format("%010d", timeStampSec);// 当前时间
//        System.out.println(Long.valueOf(endTimeStamp).compareTo(Long.valueOf(timestamp))>0);
//    }


}
