package com.metoo.nspm.core.service.api.zabbix.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostInterfaceService;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostService;
import com.metoo.nspm.dto.zabbix.HostInterfaceDTO;
import io.github.hengyunabc.zabbix.api.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ZabbixHostInterfaceServiceImpl implements ZabbixHostInterfaceService {

    @Autowired
    private ZabbixApiUtil zabbixApiUtil;
    @Autowired
    private ZabbixHostService zabbixHostService;


    @Override
    public JSONObject getHostInterface(HostInterfaceDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "hostinterface.get");
        return zabbixApiUtil.call(request);
    }

    @Override
    public JSONObject getHostInterfaceByIp(String ip) {
        String hostid = this.zabbixHostService.getHostId(ip);
        HostInterfaceDTO dto = new HostInterfaceDTO();
        dto.setHostids(String.valueOf(hostid));
        Request request = this.zabbixApiUtil.parseParam(dto, "hostinterface.get");
        return zabbixApiUtil.call(request);
    }

    @Override
    public String getHostInterfaceIdByHostId(String hostid) {
        HostInterfaceDTO dto = new HostInterfaceDTO();
        dto.setHostids(String.valueOf(hostid));
        Request request = this.zabbixApiUtil.parseParam(dto, "hostinterface.get");
        JSONObject requestResult = zabbixApiUtil.call(request);
        JSONArray results = JSONArray.parseArray(requestResult.getString("result"));
        if(requestResult.getString("result") != null && results.size() > 0){
            JSONObject result = JSONObject.parseObject(results.get(0).toString());
            return result.getString("interfaceid");
        }
        return "";
    }

    @Override
    public String getInterfaceAvaliable(String ip) {
        JSONObject jsonObject = this.getHostInterfaceByIp(ip);
        JSONArray results = JSONArray.parseArray(jsonObject.getString("result"));
        if(jsonObject.getString("result") != null && results.size() > 0){
            JSONObject result = JSONObject.parseObject(results.get(0).toString());
            return result.getString("available");
        }
        return "-1";
    }

    @Override
    public JSONObject getHostInterfaceInfo(String ip) {
        JSONObject jsonObject = this.getHostInterfaceByIp(ip);
        if(jsonObject.getString("result") != null){
            JSONArray results = JSONArray.parseArray(jsonObject.getString("result"));
            if(results.size() > 0){
                JSONObject result = JSONObject.parseObject(results.get(0).toString());
                return result;
            }
        }
        return new JSONObject();
    }

    @Override
    public JSONObject update(HostInterfaceDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "hostinterface.update");
        JSONObject result = zabbixApiUtil.call(request);
        return result;
    }

}
