package com.metoo.nspm.core.service.nspm.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostService;
import com.metoo.nspm.core.service.nspm.ZabbixProblemService;
import com.metoo.nspm.dto.zabbix.ProblemDTO;
import io.github.hengyunabc.zabbix.api.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Calendar;

@Service
public class ZabbixProblemServiceImpl implements ZabbixProblemService {

    @Autowired
    private ZabbixApiUtil zabbixApiUtil;
    @Autowired
    private ZabbixHostService zabbixHostService;


    @Override
    public JSONObject get(ProblemDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "problem.get");
        return zabbixApiUtil.call(request);
    }

    public static void main(String[] args) {
        Calendar beforeTime = Calendar.getInstance();
        beforeTime.add(Calendar.MINUTE, -1);// -1分钟之前的时间
        Long time = beforeTime.getTime().getTime();
        System.out.println(time);
        System.out.println(time / 1000);
    }

    public JSONArray getProblemByIp(String ip, Long time, boolean recent){
        String hostid = this.zabbixHostService.getHostId(ip);
        if(hostid != null){
            ProblemDTO dto = new ProblemDTO();
            dto.setHostids(Arrays.asList(hostid));
            dto.setSelectTags("extend");
//            Calendar beforeTime = Calendar.getInstance();
//            beforeTime.add(Calendar.MINUTE, -1);// -1分钟之前的时间
//            Long time = beforeTime.getTime().getTime() / 1000;
            dto.setTime_from(time);
            dto.setRecent(recent);
            JSONObject problem = this.get(dto);
            if(problem.get("result") != null) {
                JSONArray itemArray = JSONArray.parseArray(problem.getString("result"));
                return itemArray;
            }
        }
        return new JSONArray();
    }


}
