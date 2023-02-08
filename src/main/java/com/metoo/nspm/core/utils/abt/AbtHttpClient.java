package com.metoo.nspm.core.utils.abt;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.httpclient.UrlConvertUtil;
import com.metoo.nspm.entity.nspm.SysConfig;
import org.apache.commons.beanutils.BeanMap;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Component
public class AbtHttpClient {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private UrlConvertUtil urlConvertUtil;
    @Autowired
    private RestTemplate restTemplate;

    public <T> JSONObject post(String url, T t, String contentType){
        // 转换url
        url = this.urlConvertUtil.convert(url);
        // java bean转Map
        Map<String, Object> beanMap = new BeanMap(t);
        // 筛选参数
        MultiValueMap<String, Object> params = new LinkedMultiValueMap<String, Object>();
        for(String key : beanMap.keySet()){
            if(beanMap.get(key) != null){
                params.set(key, beanMap.get(key));
            }
        }
        params.remove("class");
        // 获取第三方token
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        return this.sendPost(params, url, token, contentType);
    }

    public JSONObject sendPost(MultiValueMap<String, Object> map, String url, String token, String content_type) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);// 设置密钥
        if(content_type.equals("x-www-form-urlencoded")){
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        }
        HttpEntity<MultiValueMap<String, Object>> httpEntity = new HttpEntity<>(map,headers);
        ResponseEntity<String> exchange = restTemplate.exchange(url, HttpMethod.POST, httpEntity, String.class);
        if (exchange.getStatusCodeValue() == 200 && StringUtils.isNotEmpty(exchange.getBody())) {
            String body = exchange.getBody();
            JSONObject jsonObject = null;
            try {
                jsonObject = JSONObject.parseObject(body);
                return jsonObject;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }

}
