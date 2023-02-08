package com.metoo.nspm.core.service.api.zabbix.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostInterfaceService;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostService;
import com.metoo.nspm.dto.zabbix.HostDTO;
import io.github.hengyunabc.zabbix.api.DeleteRequest;
import io.github.hengyunabc.zabbix.api.Request;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Service
public class ZabbixHostServiceImpl implements ZabbixHostService {

    @Autowired
    private ZabbixApiUtil zabbixApiUtil;
    @Autowired
    private ZabbixHostService zabbixHostService;
    @Autowired
    private ZabbixHostInterfaceService zabbixHostInterfaceService;

    @Override
    public JSONObject getHost(HostDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "host.get");
        return zabbixApiUtil.call(request);
    }

    @Override
    public String getHostId(String ip) {
        // 查询当前主机是否有效
        HostDTO dto = new HostDTO();
        Map map = new HashMap();
        map.put("ip", Arrays.asList(ip));
        dto.setFilter(map);
        dto.setMaintenance_status(true);
        JSONObject hosts = this.getHost(dto);
        if(hosts.get("result") != null){
            JSONArray arrays = JSONArray.parseArray(hosts.getString("result"));
            if(arrays.size() > 0){
                JSONObject host = JSONObject.parseObject(arrays.get(0).toString());
                String hostid = host.getString("hostid");
                return hostid;
            }
        }
        return "";
    }

    @Override
    public boolean getHostMaintenanceStatus(String ip) {
        // 查询当前主机是否有效
        HostDTO dto = new HostDTO();
        Map map = new HashMap();
        map.put("ip", Arrays.asList(ip));
        dto.setFilter(map);
        dto.setMaintenance_status(true);
        JSONObject hosts = this.getHost(dto);
        if(hosts.get("result") != null){
            JSONArray arrays = JSONArray.parseArray(hosts.getString("result"));
            if(arrays.size() > 0){
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean verifyHost(String ip) {
        if(ip != null){
            // 验证当前主机是否可用
            String available = this.zabbixHostInterfaceService.getInterfaceAvaliable(ip);
            if(available.equals(2)){
                return false;
            }
            // 验证当前主机是否启用
            boolean status = this.zabbixHostService.getHostMaintenanceStatus(ip);
            if(!status){
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean deleteHost(String ip) {
        String hostId =  this.getHostId(ip);
        if(!StringUtils.isEmpty(hostId)){
            HostDTO dto = new HostDTO();
            dto.setHostid(hostId);
            DeleteRequest request = this.zabbixApiUtil.parseArrayParam(dto, "host.delete");
            JSONObject result = zabbixApiUtil.call(request);
            JSONObject error = JSONObject.parseObject(result.getString("error"));
            if(error == null){
                return true;
            }
            return false;
        }
        return true;
    }

}
