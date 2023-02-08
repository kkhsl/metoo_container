package com.metoo.nspm.core.service.phpipam.impl;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.http.IpamApiUtil;
import com.metoo.nspm.core.service.phpipam.IpamAddressService;
import com.metoo.nspm.entity.Ipam.IpamAddress;
import org.springframework.cglib.beans.BeanMap;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Service
public class IpamAddressServiceImpl implements IpamAddressService {


    @Override
    public JSONObject addresses(Integer id, String path) {
        String url = "/addresses/";
        if(id != null){
            url += id;
        }
        if(path != null){
            url += "/" + path;
        }
        IpamApiUtil base = new IpamApiUtil(url);
        return base.get();
    }

    @Override
    public JSONObject create(IpamAddress instance) {
        String url = "/addresses/";
        Map<String, Object> map =  beanToMap(instance, true);
        IpamApiUtil base = new IpamApiUtil(url, map);
        return base.post();
    }

    @Override
    public JSONObject update(IpamAddress instance) {
        String url = "/addresses/";
        Map<String, Object> map =  beanToMap(instance, true);
        IpamApiUtil base = new IpamApiUtil(url, map);
        return base.patch();
    }


    @Override
    public JSONObject remove(Integer id, String path) {
        String url = "/addresses/";
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

