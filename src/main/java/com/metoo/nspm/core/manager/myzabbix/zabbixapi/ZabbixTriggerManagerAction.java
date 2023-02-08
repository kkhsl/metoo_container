package com.metoo.nspm.core.manager.myzabbix.zabbixapi;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.dto.zabbix.ParamsDTO;
import com.metoo.nspm.dto.zabbix.TriggerDTO;
import io.github.hengyunabc.zabbix.api.Request;
import io.github.hengyunabc.zabbix.api.RequestBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RequestMapping("/zabbix/trigger")
@RestController
public class ZabbixTriggerManagerAction {

    @Autowired
    private ZabbixApiUtil zabbixApiUtil;


}
