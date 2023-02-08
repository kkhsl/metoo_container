package com.metoo.nspm.core.manager.myzabbix.zabbixapi;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.github.pagehelper.util.StringUtil;
import com.metoo.nspm.dto.zabbix.*;
import io.github.hengyunabc.zabbix.api.Request;
import io.github.hengyunabc.zabbix.api.RequestBuilder;
import io.swagger.annotations.Api;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Api("Zabbix")
@RequestMapping("/zabbixapi")
@RestController
public class ZabbixApiManagerController {

    @Autowired
    private ZabbixApiUtil zabbixApiUtil;

    @RequestMapping("/host")
    public Object host1(HostDTO dto){
        Request request = this.parseParam(dto, "host.get");
        return zabbixApiUtil.call(request);
    }

    @RequestMapping("/item")
    public Object item(ItemDTO dto){
        Request request = this.parseParam(dto, "item.get");
        return zabbixApiUtil.call(request);
    }

    @RequestMapping("/history")
    public Object history(HistoryDTO dto){
        Request request = this.parseParam(dto, "history.get");
        return zabbixApiUtil.call(request);
    }

    @RequestMapping("/trigger")
    public Object trigger(HistoryDTO dto){
        Request request = this.parseParam(dto, "trigger.get");
        return zabbixApiUtil.call(request);
    }

    @PostMapping("/trigger/create")
    public Object create(@RequestBody TriggerDTO dto){
        Request request = this.parseParam(dto, "trigger.create");
        return zabbixApiUtil.call(request);
    }

    @RequestMapping("/problem")
    public Object trigger(ProblemDTO dto){
        Request request = this.parseParam(dto, "problem.get");
        return zabbixApiUtil.call(request);
    }

    @RequestMapping("/template")
    public Object template(@RequestBody(required = false) TemplateDTO dto){
        if(StringUtil.isEmpty(dto.getVendor())){
            return ResponseUtil.badArgument("厂商必填）");
        }
        Request request = this.parseParam(dto, "template.get");
        JSONObject json = zabbixApiUtil.call(request);
        JSONArray results = JSONArray.parseArray(json.getString("result"));
        if(results.size() > 0){
            List list = new ArrayList();
            for (Object result : results){
                JSONObject element = JSONObject.parseObject(result.toString());
                if(element.getString("host").equalsIgnoreCase(dto.getVendor() + " common")){
                    list.add(result);
                }
            }
            return ResponseUtil.ok(list);
        }
        return ResponseUtil.ok();
    }

    public Request parseParam(ParamsDTO dto, String method){
        RequestBuilder requestBuilder = RequestBuilder.newBuilder().method(method);
        if(dto != null){
            System.out.println(JSONObject.toJSONString(dto));
            JSONObject json = JSONObject.parseObject(JSONObject.toJSONString(dto));
            for(Map.Entry<String, Object> entry : json.entrySet()){
                String key = entry.getKey();
                Object value = entry.getValue();
                if(value != null){
                    requestBuilder.paramEntry(key, value);
                }
            }
        }
        return requestBuilder.build();
    }

    @RequestMapping("/usermacro/get")
    public Object usermacroGet(@RequestBody UserMacroDTO dto){
        Request request = this.parseParam(dto, "usermacro.get");
        return zabbixApiUtil.call(request);
    }

}
