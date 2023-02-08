package com.metoo.nspm.core.service.api.zabbix.impl;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.core.service.api.zabbix.ITriggerService;
import com.metoo.nspm.dto.zabbix.HistoryDTO;
import com.metoo.nspm.dto.zabbix.TriggerDTO;
import com.metoo.nspm.dto.zabbix.UserMacroDTO;
import io.github.hengyunabc.zabbix.api.DeleteRequest;
import io.github.hengyunabc.zabbix.api.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TriggerServiceImpl implements ITriggerService {

    @Autowired
    private ZabbixApiUtil zabbixApiUtil;

    @Override
    public JSONObject get(TriggerDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "trigger.get");
        return zabbixApiUtil.call(request);
    }

    @Override
    public JSONObject create(TriggerDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "trigger.create");
        return zabbixApiUtil.call(request);
    }

    @Override
    public JSONObject update(TriggerDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "trigger.update");
        return zabbixApiUtil.call(request);
    }

    @Override
    public JSONObject delete(TriggerDTO dto) {
        DeleteRequest request = this.zabbixApiUtil.parseArrayParam(dto, "trigger.delete");
//        Request request = this.zabbixApiUtil.parseParam(dto, "trigger.delete");
        return zabbixApiUtil.call(request);
    }

    @Override
    public JSONObject createTrigger(TriggerDTO dto) {
        JSONObject items = this.create(dto);
        if(items.get("result") != null) {
            JSONObject jsonObject = JSONObject.parseObject(items.getString("result"));
            return jsonObject;
        }else if(items.get("error") != null){
            JSONObject jsonObject = JSONObject.parseObject(items.getString("error"));
            return jsonObject;
        }
        return new JSONObject();
    }

    @Override
    public JSONObject updateTrigger(TriggerDTO dto) {
        JSONObject items = this.update(dto);
        if(items.get("result") != null) {
            JSONObject jsonObject = JSONObject.parseObject(items.getString("result"));
            return jsonObject;
        }else if(items.get("error") != null){
            JSONObject jsonObject = JSONObject.parseObject(items.getString("error"));
            return jsonObject;
        }
        return new JSONObject();
    }

    @Override
    public JSONObject deleteTrigger(TriggerDTO dto) {
        JSONObject items = this.delete(dto);
        if(items.get("result") != null) {
            JSONObject jsonObject = JSONObject.parseObject(items.getString("result"));
            return jsonObject;
        }else if(items.get("error") != null){
            JSONObject jsonObject = JSONObject.parseObject(items.getString("error"));
            return jsonObject;
        }
        return new JSONObject();
    }

}
