package com.metoo.nspm.core.service.phpipam.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.http.IpamApiUtil;
import com.metoo.nspm.core.service.phpipam.IpamSubnetService;
import com.metoo.nspm.entity.Ipam.IpamSubnet;
import org.springframework.cglib.beans.BeanMap;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Service
public class IpamSubnetServiceImpl implements IpamSubnetService {

    @Override
    public JSONObject subnets(Integer id, String path) {
        String url = "/subnets/";
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
    public Integer getSubnetsBySubnet(String subnet, Integer mask) {
        if(subnet != null && mask != null) {
            String path = "/subnets/search/" + subnet + "/" + mask;
            IpamApiUtil base = new IpamApiUtil(path);
            Object body = base.get();
            if (body != null) {
                JSONObject result = JSONObject.parseObject(body.toString());
                if (result != null && result.getBoolean("success")) {
                    JSONArray data = JSONArray.parseArray(result.getString("data"));
                    JSONObject ele = JSONObject.parseObject(data.get(0).toString());
                    return ele.getInteger("id");
                }
                return null;
            }
        }
        return null;
    }



    @Override
    public JSONObject create(IpamSubnet ipamSubnet) {
        String url = "/subnets/";
        Map<String, Object> map =  beanToMap(ipamSubnet, true);
        IpamApiUtil base = new IpamApiUtil(url, map);
        return base.post();
    }

    @Override
    public JSONObject update(IpamSubnet ipamSubnet) {
        String url = "/subnets/";
        Map<String, Object> map =  beanToMap(ipamSubnet, true);
        IpamApiUtil base = new IpamApiUtil(url, map);
        return base.patch();
    }

    @Override
    public JSONObject remove(Integer id, String path) {
        String url = "/subnets/";
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
