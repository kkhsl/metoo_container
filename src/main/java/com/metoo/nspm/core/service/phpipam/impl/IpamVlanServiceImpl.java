package com.metoo.nspm.core.service.phpipam.impl;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.http.IpamApiUtil;
import com.metoo.nspm.core.service.phpipam.IpamVlanService;
import com.metoo.nspm.entity.Ipam.IpamVlan;
import org.springframework.cglib.beans.BeanMap;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Service
public class IpamVlanServiceImpl implements IpamVlanService {

    @Override
    public Object vlan(Integer id) {
        String url = "/vlan/";
        if(id != null){
            url += id;
        }
        IpamApiUtil base = new IpamApiUtil(url);
        Object body = base.get();
        if (body != null) {
            JSONObject result = JSONObject.parseObject(body.toString());
            if (result != null && result.getBoolean("success")) {
                return result.get("data");
            }
            return null;
        }
        return null;
    }

    @Override
    public Object vlanSubnets(Integer id) {
        String url = "/vlan/";
        if(id != null){
            url += id + "/subnets";
        }
        IpamApiUtil base = new IpamApiUtil(url);
        Object body = base.get();
        if (body != null) {
            JSONObject result = JSONObject.parseObject(body.toString());
            if (result != null && result.getBoolean("success")) {
                return result.get("data");
            }
            return null;
        }
        return null;
    }

    @Override
    public JSONObject create(IpamVlan instance) {
        String url = "/vlan/";
        Map<String, Object> map =  beanToMap(instance, true);
        IpamApiUtil base = new IpamApiUtil(url, map);
        return base.post();
    }

    @Override
    public JSONObject update(IpamVlan instance) {
        String url = "/vlan/";
        Map<String, Object> map =  beanToMap(instance, true);
        IpamApiUtil base = new IpamApiUtil(url, map);
        return base.patch();
    }

    @Override
    public JSONObject remove(Integer id, String path) {
        String url = "/vlan/";
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
