//package com.cloud.tv.core.http;
//
//import ISysConfigService;
//import SysConfig;
//import org.apache.commons.beanutils.BeanMap;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Component;
//import org.springframework.util.LinkedMultiValueMap;
//import org.springframework.util.MultiValueMap;
//
//import java.util.Map;
//
//@Component
//public class HttpTools {
//
//    @Autowired
//    private ISysConfigService sysConfigService;
//
//    /**
//     * 发送Get请求
//     * @return
//     */
//    public <T> Object get(String url, T t){
//        SysConfig sysConfig = this.sysConfigService.findSysConfigList();
//        url = sysConfig.getNspmUrl() + url;
//        String token = sysConfig.getNspmToken();
//
//        Map<String, Object> map = new BeanMap(t);
//        MultiValueMap<String, Object> multValueMap = new LinkedMultiValueMap<String, Object>();
//        for(String key : map.keySet()){
//            multValueMap.set(key, map.get(key));
//        }
//        HttpBase httpBase = new HttpBase(url, token,multValueMap);
//        Object  result = httpBase.get();
//        return result;
//    }
//
//    /**
//     * 发送post请求
//     * @return
//     */
//    public Object post(){
//        return null;
//    }
//}
