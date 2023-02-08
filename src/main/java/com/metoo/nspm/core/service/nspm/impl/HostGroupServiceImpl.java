package com.metoo.nspm.core.service.nspm.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.core.service.nspm.IHostGroupService;
import com.metoo.nspm.dto.zabbix.HostGroupDTO;
import io.github.hengyunabc.zabbix.api.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class HostGroupServiceImpl implements IHostGroupService {

    @Autowired
    private ZabbixApiUtil zabbixApiUtil;

    private static final String NAME = "METOO-OMAP";

    @Override
    public JSONObject get(HostGroupDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "hostgroup.get");
        return zabbixApiUtil.call(request);
    }

    @Override
    public String getHostGroupId() {
        HostGroupDTO dto = new HostGroupDTO();
//        dto.setName(Arrays.asList(NAME));
        Map map = new HashMap();
        map.put("name", "METOO-OMAP");
        dto.setFilter(map);
        Request request = this.zabbixApiUtil.parseParam(dto, "hostgroup.get");
        JSONObject json = zabbixApiUtil.call(request);
        if(json.getString("result") != null){
            JSONArray results = JSONArray.parseArray(json.getString("result"));
            if(results.size() > 0){
                for (Object result : results){
                    JSONObject element = JSONObject.parseObject(result.toString());
                    return element.getString("groupid");
                }
            }
        }
        return "";
    }
}
