package com.metoo.nspm.core.manager.myzabbix.utils;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.dto.zabbix.ParamsDTO;
import io.github.hengyunabc.zabbix.api.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.Map;

/**
 * 修改为单例模式；连接超时时间，避免多线程访问zabbix时，导致长时间无响应；批量访问zabbix时，首先校验zabbix是否可用
 */
@Component
public class ZabbixApiUtil {

    public static String BASE_URL;
    public static final String USER = "Admin";// 默认账号
    public static final String PASSWORD = "zabbix";// 默认密码
    public static ZabbixApi ZABBIX_API = null;// ZabbixApi实例

    @Value("${zabbix.url}")
    public void setUrl(String url) {
        ZabbixApiUtil.BASE_URL= url;
    }

//    @PostConstruct
    public void init() {
        ZabbixApi zabbixApi = new DefaultZabbixApi(BASE_URL);
        zabbixApi.init();
        try {
            zabbixApi.login(ZabbixApiUtil.USER, ZabbixApiUtil.PASSWORD);
            ZABBIX_API = zabbixApi;
        } catch (Exception e) {
            e.printStackTrace();
            ZABBIX_API = null;
        }
    }

    public static void verifyZabbix(){// UnknownHostException
        if(ZABBIX_API == null){
            ZabbixApi zabbixApi = new DefaultZabbixApi(BASE_URL);
            zabbixApi.init();
            try {
                zabbixApi.login(ZabbixApiUtil.USER, ZabbixApiUtil.PASSWORD);
                ZABBIX_API = zabbixApi;
            } catch (Exception e) {
                e.printStackTrace();
                ZABBIX_API = null;
            }
        }
    }

    public static JSONObject call(Request request){// UnknownHostException
        isAvaliability();
        if(ZABBIX_API != null){
            JSONObject resJson = null;
            try {
                resJson = ZABBIX_API.call(request);
                return resJson;
            } catch (Exception e) {
                e.printStackTrace();
                return new JSONObject();
            }
        }
        return new JSONObject();
    }

    public static JSONObject call(DeleteRequest request){
        JSONObject resJson = ZABBIX_API.call(request);
        return resJson;
    }


    public static Request parseParam(ParamsDTO dto, String method){
        RequestBuilder requestBuilder = RequestBuilder.newBuilder().method(method);
        if(dto != null){
            JSONObject json = JSONObject.parseObject(JSONObject.toJSONString(dto));
            for(Map.Entry<String, Object> entry : json.entrySet()){
                String key = entry.getKey();
                Object value = entry.getValue();
                if(value != null){
                    requestBuilder.paramEntry(key, value);
                }
            }
        }
        return requestBuilder.build();
    }

    public static DeleteRequest parseArrayParam(ParamsDTO dto, String method){
        DeleteRequestBuild deleteRequestBuild = DeleteRequestBuild.newBuilder().method(method);
        if(dto != null){
            JSONObject json = JSONObject.parseObject(JSONObject.toJSONString(dto));
            for(Map.Entry<String, Object> entry : json.entrySet()){
                String key = entry.getKey();
                Object value = entry.getValue();
                if(value != null){
                    deleteRequestBuild.paramEntry(Integer.parseInt(value.toString()));
                }
            }
        }
        return deleteRequestBuild.build();
    }

    // 校验Api是否可用
    public static void isAvaliability() {
        if(ZABBIX_API == null){
            ZabbixApi zabbixApi = new DefaultZabbixApi(BASE_URL);
            zabbixApi.init();
            try {
                zabbixApi.login(ZabbixApiUtil.USER, ZabbixApiUtil.PASSWORD);
                ZABBIX_API = zabbixApi;
            } catch (Exception e) {
                e.printStackTrace();
                ZABBIX_API = null;
            }
        }
    }
}
