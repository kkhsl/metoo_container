package com.metoo.nspm.core.service.phpipam.impl;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.http.IpamApiUtil;
import com.metoo.nspm.core.service.phpipam.IpamL2DomainService;
import com.metoo.nspm.entity.Ipam.IpamDomain;
import org.springframework.cglib.beans.BeanMap;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;


@Service
public class IpamL2DoaminServiceImpl implements IpamL2DomainService {

    @Override
    public JSONObject l2domains(Integer id) {
        String url = "/l2domains/";
        if(id != null){
            url += id;
        }
        IpamApiUtil base = new IpamApiUtil(url);
        Object body = base.get();
        JSONObject result = JSONObject.parseObject(body.toString());
        return result;
    }

    @Override
    public JSONObject vlans(Integer id) {
        String url = "/l2domains/";
        if (id != null) {
            url += id + "/" + "/vlans";

        }
        IpamApiUtil base = new IpamApiUtil(url);
        Object body = base.get();
        JSONObject result = JSONObject.parseObject(body.toString());
        return result;
    }

    @Override
    public JSONObject create(IpamDomain instance) {
        String url = "/l2domains/";
        Map<String, Object> map =  beanToMap(instance, true);
        IpamApiUtil base = new IpamApiUtil(url, map);
        return base.post();
    }

    @Override
    public JSONObject update(IpamDomain instance) {
        String url = "/l2domains/";
        Map<String, Object> map =  beanToMap(instance, true);
        IpamApiUtil base = new IpamApiUtil(url, map);
        return base.patch();
    }

    @Override
    public JSONObject remove(Integer id, String path) {
        String url = "/l2domains/";
        if(id != null){
            url += id;
        }
        if(path != null){
            url += "/" + path;
        }
        IpamApiUtil base = new IpamApiUtil(url);
        return base.del();
    }

    @SuppressWarnings("unchecked")
    public static <T> Map<String, Object> beanToMap(T bean, boolean ignoreNullValue) {
        BeanMap beanMap = BeanMap.create(bean);
        Map<String, Object> map = new HashMap<>(beanMap.size());
        beanMap.forEach((key, value) -> {
            if (ignoreNullValue && Objects.nonNull(value)) {
                map.put(String.valueOf(key), value);
            }
            if (!ignoreNullValue) {
                map.put(String.valueOf(key), value);
            }
        });
        return map;
    }
}
