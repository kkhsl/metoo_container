package com.metoo.nspm.core.manager.myzabbix.zabbixapi;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.core.service.nspm.IHostGroupService;
import com.metoo.nspm.core.service.api.zabbix.ITemplateService;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostInterfaceService;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.zabbix.HostCreateDTO;
import com.metoo.nspm.dto.zabbix.HostDTO;
import com.metoo.nspm.dto.zabbix.HostInterfaceDTO;
import io.github.hengyunabc.zabbix.api.DeleteRequest;
import io.github.hengyunabc.zabbix.api.Request;
import io.swagger.annotations.Api;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Api("Host")
@RequestMapping("/zabbixapi/host")
@RestController
public class ZabbixHostManagerAction {

    @Autowired
    private ZabbixApiUtil zabbixApiUtil;
    @Autowired
    private IHostGroupService hostGroupService;
    @Autowired
    private ITemplateService templateService;
    @Autowired
    private ZabbixHostInterfaceService zabbixHostInterfaceService;
    @Autowired
    private ZabbixHostService zabbixHostService;


    // 获取模板
    @RequestMapping("/template")
    public Object template(String ip){
        HostDTO dto = new HostDTO();
//        dto.setSelectParentTemplates(Arrays.asList("templateid", "name"));
        Map map = new HashMap();
        map.put("name", "Metoo_network_Common");
        dto.setFilter(map);
        Request request = this.zabbixApiUtil.parseParam(dto, "template.get");
        return ResponseUtil.ok(zabbixApiUtil.call(request).get("result"));
    }

    // 获取分组
    @RequestMapping("/hostgroup")
    public Object hostgroup(String ip){
        HostDTO dto = new HostDTO();
//        dto.setSelectParentTemplates(Arrays.asList("hostgroup", "name"));
        Map map = new HashMap();
//        map.put("ip", Arrays.asList(ip));
        map.put("name", "METOO-OMAP");
        dto.setFilter(map);
        Request request = this.zabbixApiUtil.parseParam(dto, "hostgroup.get");
        return ResponseUtil.ok(zabbixApiUtil.call(request).get("result"));
    }


    @RequestMapping("/get")
    public Object get(String ip){
        HostDTO dto = new HostDTO();
//        dto.setSelectParentTemplates(Arrays.asList("templateid", "name"));
        Map map = new HashMap();
        if(StringUtils.isNotEmpty(ip)){
            map.put("ip", Arrays.asList(ip));
            dto.setFilter(map);
        }
        Request request = this.zabbixApiUtil.parseParam(dto, "host.get");
        return ResponseUtil.ok(zabbixApiUtil.call(request).get("result"));
    }

    @RequestMapping("/create")
    public Object create(@RequestBody(required = false) HostCreateDTO instance){
        // 判断ip对应的实际是否已存在
        instance.setName(instance.getIp());
        instance.setHost(instance.getIp());
        Map interfaces = new HashMap();
        interfaces.put("type", instance.getType());// 1 - agent; 2 - SNMP; 3 - IPMI; 4 - JMX
        interfaces.put("main",  "1");//  该接口是否在主机上用作默认的接口，在主机上只能将某种类型的一个接口设置为默认值 0 - 不是默认 1 - 默认
        interfaces.put("useip", "1");// 	是否通过IP进行连接。 0 - 使用主机DNS进行连接; 1 - 使用主机接口的主机IP进行连接。
        interfaces.put("ip", instance.getIp());// 接口使用的IP地址 如果使用DNS域名连接，可以设置为空。
        interfaces.put("dns", "");// 	接口使用的DNS名称 如果通过IP直接连接，则可以为空。
        interfaces.put("port", instance.getPort() == null || instance.getPort().equals("") ? "161"
                : instance.getPort());// 接口使用的端口号，可以包含用户宏
        Map details  = new HashMap();
        details.put("version", instance.getVersion());// 1 - SNMPv1; 2 - SNMPv2c; 3 - SNMPv3
        details.put("bulk", "0");// 0 - 不使用批量请求; 1 - (默认) - 使用批量请求。
        details.put("community", instance.getCommunity()); // SNMP 团体字 (必选)。 仅在SNMPv1和SNMPv2接口中使用。
        details.put("securityname", instance.getSecurityname());// 	SNMPv3 安全名称。仅在SNMPv3接口中使用
        details.put("contextname", instance.getContextname());// 	SNMPv3上下文名称。仅在SNMPv3接口中使用
        details.put("securitylevel", instance.getSecuritylevel());
        interfaces.put("details", details);


        String hostId =  this.zabbixHostService.getHostId(instance.getIp());
        if(!StringUtils.isNotEmpty(hostId)){
            HostCreateDTO dto = new HostCreateDTO();
            dto.setHost(instance.getIp());
            dto.setName(instance.getIp());
            // 设置默认主机组
            String groupId = this.hostGroupService.getHostGroupId();
            Map group  = new HashMap();
            group.put("groupid", groupId);
            dto.setGroups(Arrays.asList(group));
            String templateid = this.templateService.getTemplateId();
            Map template  = new HashMap();
            template.put("templateid", templateid);
            dto.setTemplates(Arrays.asList(template));
            dto.setInterfaces(Arrays.asList(interfaces));

            Request request = this.zabbixApiUtil.parseParam(dto, "host.create");
            JSONObject result = zabbixApiUtil.call(request);
            JSONObject error = JSONObject.parseObject(result.getString("error"));
            if(error == null){
                return ResponseUtil.ok();
            }
            return ResponseUtil.error(error.getString("data"));
        }else{
            String interfaceId = this.zabbixHostInterfaceService.getHostInterfaceIdByHostId(hostId);
            HostInterfaceDTO interfaceDTO = new HostInterfaceDTO();
            interfaceDTO.setInterfaceid(interfaceId);
            interfaceDTO.setPort(instance.getPort());
            interfaceDTO.setDetails(details);
            JSONObject interfaceResult = this.zabbixHostInterfaceService.update(interfaceDTO);
            JSONObject error = JSONObject.parseObject(interfaceResult.getString("error"));
            if(error == null){
                return ResponseUtil.ok();
            }
            return ResponseUtil.error(error.getString("data"));
        }
    }

    @RequestMapping("/update")
    public Object update(String ip){
        Map map = new HashMap();
        JSONObject hostInterfaces = this.zabbixHostInterfaceService.getHostInterfaceByIp(ip);
        if(hostInterfaces.get("result") != null){
            JSONArray arrays = JSONArray.parseArray(hostInterfaces.getString("result"));
            if(arrays.size() > 0){
                JSONObject hostInterface = JSONObject.parseObject(arrays.get(0).toString());
                map.put("ip", hostInterface.getString("ip"));
                map.put("type", hostInterface.getString("type"));
                map.put("port", hostInterface.getString("port"));
                if(hostInterface.getString("details") != null){
                    JSONObject details = JSONObject.parseObject(hostInterface.getString("details"));
                    map.put("community", details.getString("community"));
                }
            }
        }
        return ResponseUtil.ok(map);
    }

//    @RequestMapping("/update")
//    public Object update(@RequestBody(required = false) HostCreateDTO dto){
//        Request request = this.zabbixApiUtil.parseParam(dto, "host.update");
//        JSONObject result  zabbixApiUtil.call(request);
//        JSONObject error = JSONObject.parseObject(result.getString("error"));
//        if(error == null){
//            return ResponseUtil.ok();
//        }
//        return ResponseUtil.error(error.getString("data"));
//    }

    @RequestMapping("/delete")
    public Object delete(@RequestBody(required = false) HostDTO dto){
        DeleteRequest request = this.zabbixApiUtil.parseArrayParam(dto, "host.delete");
        JSONObject result = zabbixApiUtil.call(request);
        JSONObject error = JSONObject.parseObject(result.getString("error"));
        if(error == null){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error(error.getString("data"));
    }

}
