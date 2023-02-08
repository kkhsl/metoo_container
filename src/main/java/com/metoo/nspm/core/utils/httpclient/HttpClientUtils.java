package com.metoo.nspm.core.utils.httpclient;


import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;

/**
 * <p>
 *     Title：HttpClientUtils.java
 * </p>
 *
 * <p>
 *     Description：Apache
 * </p>
 */
public class HttpClientUtils {

    public static String send(){
        // 声明全局变量
        InputStream is = null;
        BufferedReader reader = null;
        //1,创建HttpClient实例
        HttpClient httpClient = new DefaultHttpClient();
        //2，设置连接超时时间
        HttpGet request = new HttpGet("httpclient://127.0.0.1:9896/web/video/captcha");
        try {
            HttpResponse response = httpClient.execute(request);
            if(response.getStatusLine().getStatusCode() == HttpStatus.SC_OK){
                //获取服务器返回的json数据
                String json = EntityUtils.toString(response.getEntity());
                return json;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
