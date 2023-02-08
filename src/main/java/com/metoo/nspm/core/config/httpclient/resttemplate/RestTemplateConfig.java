package com.metoo.nspm.core.config.httpclient.resttemplate;

import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

@Configuration
public class RestTemplateConfig {

   @Bean
   public RestTemplate restTemplate()
   {
       ClientHttpRequestFactory requestFactory = null;
       try {
           requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient());
       } catch (Exception e) {

       }
       RestTemplate restTemplate = new RestTemplate(requestFactory);
       return restTemplate;
   }

    /**
     * Apache HttpClient
     * 绕过ssl 验证
     *
     * @return
     * @see [类、类#方法、类#成员]
     */
    private HttpClient httpClient() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        RequestConfig requestConfig = RequestConfig.custom()
                .setSocketTimeout(65000) // 服务器返回数据(response)的时间，超时抛出read timeout
                .setConnectTimeout(65000) // 连接上服务器(握手成功)的时间，超时抛出connect timeout
                .setConnectionRequestTimeout(1000)// 从连接池中获取连接的超时时间，超时抛出ConnectionPoolTimeoutException
                .build();
        SSLContext sslContext = SSLContextBuilder.create().setProtocol(SSLConnectionSocketFactory.SSL).loadTrustMaterial((x, y) -> true).build();
        return HttpClientBuilder.create().setDefaultRequestConfig(requestConfig).setSSLContext(sslContext).setSSLHostnameVerifier((x, y) -> true).build();
    }

}
