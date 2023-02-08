package com.metoo.nspm.core.utils;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.utils.httpclient.UrlConvertUtil;
import com.metoo.nspm.dto.TopoNodeDto;
import org.apache.commons.beanutils.BeanMap;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;

/**
 * Api类型：Http、Ldap、WebService
 */
@Component
public class NodeUtil {

    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private UrlConvertUtil urlConvertUtil;


    public Object nodeResult(TopoNodeDto dto, String url, String token) {

        if (dto != null) {
            HttpHeaders headers = new HttpHeaders();
            HttpMethod method = HttpMethod.POST;
            JSONObject postData = new JSONObject();
            // 以Json的方式提交
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("Authorization", "Bearer d8d6a5b1-de37-42bb-9d28-3b6f105900d4");
            JSONObject json = restTemplate.postForEntity(url, postData.toJSON(dto), JSONObject.class).getBody();
            return json;
        }
        return null;
    }

    public Object exchange(TopoNodeDto dto, String url, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        //设置请求参数
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url);
        Map<String, Object> map = new BeanMap(dto);
        if (!map.isEmpty()) {
            for (Map.Entry<String, Object> e : map.entrySet()) {
                builder.queryParam(e.getKey(), e.getValue());
            }
        }
        String realUrl = builder.build().toString();
        HttpEntity<JSONObject> httpEntity = new HttpEntity<>(null, headers);
        ResponseEntity<String> exchange = restTemplate.exchange(realUrl, HttpMethod.GET, httpEntity, String.class, map);
        if (StringUtils.isNotEmpty(exchange.getBody())) {
            String body = exchange.getBody();
            JSONObject jsonObject = JSONObject.parseObject(body);
            return jsonObject;
        }
        return null;
    }


    public <T> Object getBody(T t, String url, String token){
        url = this.urlConvertUtil.convert(url);
        Map<String, Object> map = new BeanMap(t);
        return this.exchange(map, url, token);
    }

    public <T> Object postBody(T t, String url, String token){
        url = this.urlConvertUtil.convert(url);
        Map<String, Object> map = new BeanMap(t);
        Map<String, Object> map1 = new HashMap();
        for(String key : map.keySet()){
            if(map.get(key) != null){
                if(key.equals("PUuid")){
                    map1.put("pUuid", map.get(key));
                }else if(key.equals("PBusinessZoneUuid")){
                    map1.put("pBusinessZoneUuid", map.get(key));
                }else{
                    map1.put(key, map.get(key));
                }

            }
        }
        map1.remove("class");
        return this.post(map1, url, token);
    }

    public <T> Object postBody(Map t, String url, String token){
        url = this.urlConvertUtil.convert(url);
        return this.post(t, url, token);
    }

    public <T> Object postFormBody(T t, String url, String token){
        url = this.urlConvertUtil.convert(url);
        Map<String, Object> map = new BeanMap(t);
        MultiValueMap<String, Object> multValueMap = new LinkedMultiValueMap<String, Object>();
        for(String key : map.keySet()){
            multValueMap.set(key, map.get(key));
        }
        return this.post_form(multValueMap, url, token);
    }

    public <T> Object postFormSend(T t, String url, String token){
        url = this.urlConvertUtil.convert(url);
        Map<String, Object> map = new BeanMap(t);
        MultiValueMap<String, Object> multValueMap = new LinkedMultiValueMap<String, Object>();
        for(String key : map.keySet()){
            multValueMap.set(key, map.get(key));
        }
        return this.postForm(multValueMap, url, token);
    }

    public <T> Object postFormDataBody(T t, String url, String token){
        url = this.urlConvertUtil.convert(url);
        Map<String, Object> map = new BeanMap(t);
        MultiValueMap<String, Object> multValueMap = new LinkedMultiValueMap<String, Object>();
        for(String key : map.keySet()){
            if(map.get(key) != null){
                multValueMap.set(key, map.get(key));
            }
        }
        multValueMap.remove("class");
        return this.post_form_data(multValueMap, url, token);
    }

    public <T> Object putBody(T t, String url, String token){
        url = this.urlConvertUtil.convert(url);
        Map<String, Object> map = new BeanMap(t);
        return this.put(map, url, token);
    }

    public <T> Object putFormDataBody(T t, String url, String token){
        url = this.urlConvertUtil.convert(url);
        Map<String, Object> map = new BeanMap(t);
        MultiValueMap<String, Object> multValueMap = new LinkedMultiValueMap<String, Object>();
        for(String key : map.keySet()){
            multValueMap.set(key, map.get(key));
        }
        return this.put_form_data(multValueMap, url, token);
    }

    public <T> Object deleteBody(T t, String url, String token){
        url = this.urlConvertUtil.convert(url);
        Map<String, Object> map = new BeanMap(t);
        return this.deleteChange(map, url, token);
    }

    public Object deleteChange(Map<String, Object> map, String url, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        //设置请求参数
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url);
        if (!map.isEmpty()) {
            for (Map.Entry<String, Object> e : map.entrySet()) {
                if(e.getValue() != null){
                    builder.queryParam(e.getKey(), e.getValue());
                }
            }
        }
        String realUrl = builder.build().toString();
        HttpEntity<JSONObject> httpEntity = new HttpEntity<>(null, headers);
        ResponseEntity<String> exchange = restTemplate.exchange(realUrl, HttpMethod.DELETE, httpEntity, String.class);
        if (StringUtils.isNotEmpty(exchange.getBody())) {
            String body = exchange.getBody();
            JSONObject jsonObject = JSONObject.parseObject(body);
            return jsonObject;
        }
        return null;
    }

    public Object exchange(Map<String, Object> map, String url, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        //设置请求参数
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url);
        if (!map.isEmpty()) {
            for (Map.Entry<String, Object> e : map.entrySet()) {
                if(e.getValue() != null){
                    builder.queryParam(e.getKey(), e.getValue());
                }
            }
        }
        String realUrl = builder.build().toString();
        HttpEntity<JSONObject> httpEntity = new HttpEntity<>(null, headers);
        ResponseEntity<String> exchange = restTemplate.exchange(realUrl, HttpMethod.GET, httpEntity, String.class);
        // ResponseEntity<String> exchange = restTemplate.exchange(realUrl, HttpMethod.GET, httpEntity, String.class, map);
        if (exchange.getStatusCodeValue() == 200 && StringUtils.isNotEmpty(exchange.getBody())) {
            String body = exchange.getBody();
            JSONObject jsonObject = JSONObject.parseObject(body);
            return jsonObject;
        }
        return null;
    }

    public Object post(Map<String, Object> map, String url, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        MediaType type = MediaType.parseMediaType("application/json");
        headers.setContentType(type);
        HttpEntity<Map<String, Object>> httpEntity = null;
        if(map.isEmpty()){
            httpEntity = new HttpEntity(headers);
        }else{
            httpEntity = new HttpEntity(map,headers);
        }
        ResponseEntity<String> exchange = restTemplate.exchange(url,HttpMethod.POST, httpEntity, String.class);
        if (exchange.getStatusCodeValue() == 200 && StringUtils.isNotEmpty(exchange.getBody())) {
            String body = exchange.getBody();
            JSONObject jsonObject = JSONObject.parseObject(body);
            return jsonObject;
        }
        return null;
    }

    public Object postForm(MultiValueMap<String, Object> map, String url, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        MediaType type = MediaType.parseMediaType("application/x-www-form-urlencoded;charset=UTF-8");
        headers.setContentType(type);
        HttpEntity<Map<String, Object>> httpEntity = null;
        if(map.isEmpty()){
            httpEntity = new HttpEntity(headers);
        }else{
            httpEntity = new HttpEntity(map,headers);
        }
        ResponseEntity<String> exchange = restTemplate.exchange(url,HttpMethod.POST, httpEntity, String.class);
        if (exchange.getStatusCodeValue() == 200 && StringUtils.isNotEmpty(exchange.getBody())) {
            String body = exchange.getBody();
            JSONObject jsonObject = JSONObject.parseObject(body);
            return jsonObject;
        }
        return null;
    }

    public Object post_form_data(MultiValueMap<String, Object> map, String url, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        HttpEntity<MultiValueMap<String, Object>> httpEntity = new HttpEntity<>(map,headers);
        ResponseEntity<String> exchange = restTemplate.exchange(url,HttpMethod.POST, httpEntity, String.class);
        if (exchange.getStatusCodeValue() == 200 && StringUtils.isNotEmpty(exchange.getBody())) {
            String body = exchange.getBody();
            JSONObject jsonObject = null;
            try {
                jsonObject = JSONObject.parseObject(body);
                return jsonObject;
            } catch (Exception e) {
                e.printStackTrace();
                return body;
            }

        }
        return null;
    }

    public Object put(Map<String, Object> map, String url, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        MediaType type = MediaType.parseMediaType("application/json; charset=UTF-8");
        headers.setContentType(type);
        HttpEntity<Map<String, Object>> httpEntity = new HttpEntity<>(map,headers);
        ResponseEntity<String> exchange = restTemplate.exchange(url,HttpMethod.PUT, httpEntity, String.class);
        if (exchange.getStatusCodeValue() == 200 && StringUtils.isNotEmpty(exchange.getBody())) {
            String body = exchange.getBody();
            JSONObject jsonObject = JSONObject.parseObject(body);
            return jsonObject;
        }
        return null;
    }

    public Object put_form_data(MultiValueMap<String, Object> map, String url, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        HttpEntity<MultiValueMap<String, Object>> httpEntity = new HttpEntity<>(map,headers);
        ResponseEntity<String> exchange = restTemplate.exchange(url,HttpMethod.PUT, httpEntity, String.class);
        if (exchange.getStatusCodeValue() == 200 && StringUtils.isNotEmpty(exchange.getBody())) {
            String body = exchange.getBody();
            JSONObject jsonObject = JSONObject.parseObject(body);
            return jsonObject;
        }
        return null;
    }

    public Object post_form(MultiValueMap<String, Object> map, String url, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, Object>> httpEntity = new HttpEntity<MultiValueMap<String, Object>>(map,headers);

        ResponseEntity<String> exchange = restTemplate.exchange(url, HttpMethod.POST,httpEntity, String.class);

        if (exchange.getStatusCodeValue() == 200 && StringUtils.isNotEmpty(exchange.getBody())) {
            String body = exchange.getBody();
            JSONObject jsonObject = JSONObject.parseObject(body);
            return jsonObject;
        }
        return null;
    }

    public ResponseEntity download(Map<String, Object> map, String url, String token){
        url = this.urlConvertUtil.convert(url);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        //设置请求参数
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url);
        if(map != null && !map.isEmpty()){
            for (Map.Entry<String, Object> e : map.entrySet()) {
                builder.queryParam(e.getKey(), e.getValue());
            }
        }
        String realUrl = builder.build().toString();
        HttpEntity<JSONObject> httpEntity = new HttpEntity<>(null, headers);
        ResponseEntity<byte[]> resEntity = restTemplate.exchange(realUrl, HttpMethod.GET, httpEntity, byte[].class);

        return resEntity;
    }

    public ResponseEntity downloadPatrol(Map<String, Object> map, String url, String token){
        url = this.urlConvertUtil.convert(url);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        //设置请求参数
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url);
        if(map != null && !map.isEmpty()){
            for (Map.Entry<String, Object> e : map.entrySet()) {
                builder.queryParam(e.getKey(), e.getValue());
            }
        }
        String realUrl = builder.build().toString();
        HttpEntity<JSONObject> httpEntity = new HttpEntity<>(null, headers);
        ResponseEntity<byte[]> resEntity = restTemplate.exchange(realUrl, HttpMethod.GET, httpEntity, byte[].class);
        return resEntity;
    }

    public ResponseEntity downloadPost(Map<String, Object> map, String url, String token){
        url = this.urlConvertUtil.convert(url);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        //设置请求参数
        MediaType type = MediaType.parseMediaType("application/json; charset=UTF-8");
        headers.setContentType(type);
        HttpEntity<Map<String, Object>> httpEntity = null;
        if(map.isEmpty()){
            httpEntity = new HttpEntity(headers);
        }else{
            httpEntity = new HttpEntity(map,headers);
        }
        ResponseEntity<byte[]> resEntity = restTemplate.exchange(url, HttpMethod.POST, httpEntity, byte[].class);

        return resEntity;
    }



}
