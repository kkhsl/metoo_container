package com.metoo.nspm.core.http;


import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.config.httpclient.resttemplate.MyRestErrorHandler;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.entity.nspm.SysConfig;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

@Component
public class NtasApiUtil {

    private static ISysConfigService sysConfigService;

    @Autowired
    public void setSysConfigService (ISysConfigService sysConfigService){
        NtasApiUtil.sysConfigService= sysConfigService;
    }

    public String TOKEN = "";
    public String BASE_URL = "/api/index.html";

    private String url;

    private Map<String, Object> map;

    public NtasApiUtil() {  }

    public NtasApiUtil(String url) {
        this.url = url;
        SysConfig sysConfig = this.sysConfigService.select();
        this.BASE_URL = sysConfig.getNtasProtocol() + "://" + sysConfig.getNtasUrl() + BASE_URL;
        this.TOKEN = sysConfig.getNtasToken();
    }

    public NtasApiUtil(String url, Map<String, Object> map) {
        this.url = url;
        this.map = map;
        SysConfig sysConfig = this.sysConfigService.select();
        this.BASE_URL = sysConfig.getNtasProtocol() + "://" + sysConfig.getNtasUrl() + BASE_URL;
        this.TOKEN = sysConfig.getNtasToken();

    }

    public NtasApiUtil(String url, String token, Map<String, Object> map) {
        this.url = url;
        this.map = map;
        SysConfig sysConfig = this.sysConfigService.select();
        this.BASE_URL = sysConfig.getNtasProtocol() + "://" + sysConfig.getNtasUrl() + BASE_URL;
        this.TOKEN = sysConfig.getNtasToken();
    }

    private static RestTemplate restTemplate;

    public ClientHttpRequestFactory init(){
        RequestConfig requestConfig = RequestConfig.custom()
                .setSocketTimeout(65000) // 服务器返回数据(response)的时间，超时抛出read timeout
                .setConnectTimeout(65000) // 连接上服务器(握手成功)的时间，超时抛出connect timeout
                .setConnectionRequestTimeout(1000)// 从连接池中获取连接的超时时间，超时抛出ConnectionPoolTimeoutException
                .build();
        SSLContext sslContext = null;
        try {
            sslContext = SSLContextBuilder.create().setProtocol(SSLConnectionSocketFactory.SSL).loadTrustMaterial((x, y) -> true).build();
            HttpClient httpClient = HttpClientBuilder.create().setDefaultRequestConfig(requestConfig).setSSLContext(sslContext).setSSLHostnameVerifier((x, y) -> true).build();
            ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
            return requestFactory;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    public JSONObject get(){
        HttpHeaders headers = new HttpHeaders();
        headers.set("token",TOKEN);// 设置密钥
        UriComponentsBuilder builder = null;
        try {
            builder = UriComponentsBuilder.fromHttpUrl(BASE_URL + url);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        if (map != null && !map.isEmpty()) {
            for(Map.Entry e : map.entrySet()){
                builder.queryParam((String) e.getKey(), e.getValue());
            }
        }
        String realUrl = builder.build().encode().toString();
        HttpEntity<JSONObject> httpEntity = new HttpEntity<>(null, headers);
        restTemplate = new RestTemplate(init());
        restTemplate.setErrorHandler(new MyRestErrorHandler());
        ResponseEntity<String> result = null;
        JSONObject jsonObject = null;
        try {
            result = restTemplate.exchange(realUrl, HttpMethod.GET, httpEntity, String.class);
            jsonObject = JSONObject.parseObject(result.getBody());
            return jsonObject;
        } catch (RestClientException e) {
            e.printStackTrace();
        }
        return jsonObject;
    }

    public JSONObject post() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("token",TOKEN);// 设置密钥
        MediaType type = MediaType.parseMediaType("application/json");
        headers.setContentType(type);
        HttpEntity<Map<String, Object>> httpEntity = null;
        if(map.isEmpty()){
            httpEntity = new HttpEntity(headers);
        }else{
            httpEntity = new HttpEntity(map,headers);
        }
        url = BASE_URL + url;
        restTemplate = new RestTemplate(init());
        restTemplate.setErrorHandler(new MyRestErrorHandler());
        ResponseEntity<String> result = null;
        JSONObject jsonObject = null;
        result = restTemplate.exchange(url, HttpMethod.POST, httpEntity, String.class);
        jsonObject = JSONObject.parseObject(result.getBody());
        return jsonObject;
    }

    public JSONObject patch() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("token",TOKEN);// 设置密钥
        MediaType type = MediaType.parseMediaType("application/json");
        headers.setContentType(type);
        HttpEntity<Map<String, Object>> httpEntity = null;
        if(map.isEmpty()){
            httpEntity = new HttpEntity(headers);
        }else{
            httpEntity = new HttpEntity(map,headers);
        }
        url = BASE_URL + url;
        restTemplate = new RestTemplate(init());
        restTemplate.setErrorHandler(new MyRestErrorHandler());
        ResponseEntity<String> result = null;
        JSONObject jsonObject = null;
        result = restTemplate.exchange(url, HttpMethod.PATCH, httpEntity, String.class);
        jsonObject = JSONObject.parseObject(result.getBody());
        return jsonObject;
    }

    public JSONObject del(){
        HttpHeaders headers = new HttpHeaders();
        headers.set("token",TOKEN);// 设置密钥
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(BASE_URL + url);
        if (map != null && !map.isEmpty()) {
            for(String key : map.keySet()){
                builder.build(key, map.get(key));
            }
        }
        String realUrl = builder.build().toString();
        HttpEntity<JSONObject> httpEntity = new HttpEntity<>(null, headers);
        restTemplate = new RestTemplate(init());
        restTemplate.setErrorHandler(new MyRestErrorHandler());
        ResponseEntity<String> result = null;
        JSONObject jsonObject = null;
        try {
            result = restTemplate.exchange(realUrl, HttpMethod.DELETE, httpEntity, String.class);
            jsonObject = JSONObject.parseObject(result.getBody());
            return jsonObject;
        } catch (RestClientException e) {
            e.printStackTrace();
        }
        return jsonObject;
    }

    // 校验Api是否可用


}
