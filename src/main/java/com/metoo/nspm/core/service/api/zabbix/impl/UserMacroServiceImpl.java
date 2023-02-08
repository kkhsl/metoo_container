package com.metoo.nspm.core.service.api.zabbix.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.core.service.api.zabbix.IUserMacroService;
import com.metoo.nspm.dto.zabbix.ItemDTO;
import com.metoo.nspm.dto.zabbix.UserMacroDTO;
import io.github.hengyunabc.zabbix.api.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserMacroServiceImpl implements IUserMacroService {

    @Autowired
    private ZabbixApiUtil zabbixApiUtil;

    @Override
    public JSONObject getUserMacro(UserMacroDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "usermacro.get");
        return zabbixApiUtil.call(request);
    }

    public JSONObject setUserMacro(UserMacroDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "usermacro.updateglobal");
        return zabbixApiUtil.call(request);
    }

    @Override
    public JSONArray getUserMacros(UserMacroDTO dto) {
        JSONObject items = this.getUserMacro(dto);
        if(items.get("result") != null) {
            JSONArray itemArray = JSONArray.parseArray(items.getString("result"));
            return itemArray;
        }
        return new JSONArray();
    }

    @Override
    public JSONObject updateUserMacros(UserMacroDTO dto) {
        JSONObject items = this.setUserMacro(dto);
        if(items.get("result") != null) {
            JSONObject jsonObject = JSONObject.parseObject(items.getString("result"));
            return jsonObject;
        }
        JSONObject jsonObject = JSONObject.parseObject(items.getString("error"));
        return  jsonObject;
    }


}
