package com.metoo.nspm.core.service.api.zabbix.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.core.service.api.zabbix.ITemplateService;
import com.metoo.nspm.dto.zabbix.TemplateDTO;
import io.github.hengyunabc.zabbix.api.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class TemplateServiceImpl implements ITemplateService {


    @Autowired
    private ZabbixApiUtil zabbixApiUtil;

    private static String NAME = "Metoo_network_Common";

    @Override
    public JSONObject getTemplate(TemplateDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "template.get");
        return zabbixApiUtil.call(request);
    }

    @Override
    public String getTemplateId() {
        TemplateDTO dto = new TemplateDTO();
        Map params = new HashMap();
        params.put("name", NAME);
        dto.setFilter(params);
        JSONObject result = this.getTemplate(dto);
        if(result.getString("result") != null){
            JSONArray results = JSONArray.parseArray(result.getString("result"));
            if(results.size() > 0){
                for (Object obj : results){
                    JSONObject element = JSONObject.parseObject(obj.toString());
                    return element.getString("templateid");
                }
            }
        }
        return "";
    }
}
