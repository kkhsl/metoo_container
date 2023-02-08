package com.metoo.nspm.core.manager.myzabbix.zabbixapi;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.JSONPObject;
import com.metoo.nspm.core.service.api.zabbix.ITriggerService;
import com.metoo.nspm.core.service.nspm.INetworkElementService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.zabbix.TriggerDTO;
import com.metoo.nspm.entity.nspm.NetworkElement;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.BasicAuthDefinition;
import io.swagger.models.auth.In;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.ws.Response;
import java.util.*;

@Api("触发器")
@RequestMapping("/zabbix/api/trigger")
@RestController
public class TriggerManagerController {

    @Autowired
    private ITriggerService triggerService;
    @Autowired
    private INetworkElementService networkElementService;

    @ApiOperation("创建触发器")
    @RequestMapping("/create")
    public Object create(@RequestBody List<TriggerDTO> dtos){
        if(dtos.size() > 0){
            for (TriggerDTO dto : dtos) {
                if(dto.getInterfaceName() != null && !dto.getInterfaceName().equals("")){
                    dto.setDescription(dto.getInterfaceName() + " :UP/DOWN");
                }
                if(dto.getIp() != null && !dto.getIndex().equals("")){
                    dto.setExpression("last(/" +
                            dto.getIp() +
                            "/net.if.status[ifOperStatus." +
                            dto.getIndex() +
                            "])=2 and\n" +
                            "last(/" +
                            dto.getIp() +
                            "/net.if.status[ifOperStatus." +
                            dto.getIndex() +
                            "],#1)<>last(/" +
                            dto.getIp() +
                            "/net.if.status[ifOperStatus." +
                            dto.getIndex() +
                            "],#2)<>0");
                    dto.setRecovery_expression("last(/" +
                            dto.getIp() +
                            "/net.if.status[ifOperStatus." +
                            dto.getIndex() +
                            "])<>2");
                }
                dto.setPriority(4);
                dto.setRecovery_mode(1);

                Map map = new HashMap();
                map.put("tag", "objalarm");
                map.put("value", "interfacestatusimportant");
                Map map2 = new HashMap();
                map2.put("tag", "ifnamealarm");
                map2.put("value", dto.getInterfaceName());
                List list = new ArrayList();
                list.add(map);
                list.add(map2);
                dto.setTags(list);
                String interfaceName = dto.getInterfaceName();
                String ip = dto.getIp();
                dto.setIp(null);
                dto.setIndex(null);
                dto.setInterfaceName(null);
                JSONObject jsonObject = this.triggerService.createTrigger(dto);
                if(jsonObject.getString("triggerids") != null){
                    JSONArray jsonArray = JSONArray.parseArray(jsonObject.getString("triggerids"));
                    if(jsonArray.size() > 0){
                        Integer triggerids = jsonArray.getInteger(0);
                        Map params = new HashMap();
                        params.put("ip", ip);
                        List<NetworkElement> networkElements = this.networkElementService.selectObjByMap(params);
                        if(networkElements.size() > 0){
                            NetworkElement networkElement = networkElements.get(0);
                            String interfaceNames = networkElement.getInterfaceNames();
                            Map ports = new HashMap();
                            if(interfaceNames != null && !interfaceNames.equals("")){
                                ports = JSONObject.parseObject(interfaceNames, Map.class);
                            }
                            ports.put(interfaceName, triggerids);
                            networkElement.setInterfaceNames(JSONObject.toJSONString(ports));
                            this.networkElementService.update(networkElement);
                        }
                    }
                }else{
                    return ResponseUtil.badArgument(jsonObject.getString("data"));
                }
            }
        }
        return ResponseUtil.ok();
    }

    @ApiOperation("创建触发器")
    @RequestMapping("/create/flux")
    public Object create2(@RequestBody List<TriggerDTO> dtos){
        if(dtos.size() > 0){
            for (TriggerDTO dto : dtos) {
                Integer val = dto.getValue();
                float value =(float)(Math.round(val))/100;

                if(dto.getInterfaceName() != null && !dto.getInterfaceName().equals("")){
                    dto.setDescription(dto.getInterfaceName() + " :流量超过端口带宽的" + val +  "%");
                }
                if(dto.getIp() != null && !dto.getIndex().equals("")){
                    dto.setExpression("avg(/" +
                            dto.getIp() +
                            "/net.if.in[ifHCInOctets." +
                            dto.getIndex() +
                            "],60)>  last(/" +
                            dto.getIp() +
                            "/net.if.speed[ifHighSpeed." +
                            dto.getIndex() +
                            "])*" +
                            value +
                            " or avg(/" +
                            dto.getIp() +
                            "/net.if.out[ifHCOutOctets." +
                            dto.getIndex() +
                            "],60)> last(/" +
                            dto.getIp() +
                            "/net.if.speed[ifHighSpeed." +
                            dto.getIndex() +
                            "])*" +
                            value);
                    dto.setRecovery_expression(
                            "avg(/" +
                                    dto.getIp() +
                                    "/net.if.in[ifHCInOctets." +
                                    dto.getIndex() +
                                    "],60)< last(/" +
                                    dto.getIp() +
                                    "/net.if.speed[ifHighSpeed." +
                                    dto.getIndex() +
                                    "])*" +
                                    value +
                                    " and avg(/" +
                                    dto.getIp() +
                                    "/net.if.out[ifHCOutOctets." +
                                    dto.getIndex() +
                                    "],60)< last(/" +
                                    dto.getIp() +
                                    "/net.if.speed[ifHighSpeed." +
                                    dto.getIndex() +
                                    "])*" +
                                    value);
                }
                dto.setPriority(2);
                dto.setRecovery_mode(1);
                Map map = new HashMap();
                map.put("tag", "objalarm");
                map.put("value", "interfacetraffic");
                Map map2 = new HashMap();
                map2.put("tag", "ifnamealarm");
                map2.put("value", dto.getInterfaceName());
                List list = new ArrayList();
                list.add(map);
                list.add(map2);
                dto.setTags(list);
                String interfaceName = dto.getInterfaceName();
                String ip = dto.getIp();
                dto.setIp(null);
                dto.setIndex(null);
                dto.setInterfaceName(null);
                dto.setValue(null);
                JSONObject jsonObject = null;
                if(dto.getTriggerid() != null && !dto.getTriggerid().equals("")){
                    jsonObject = this.triggerService.updateTrigger(dto);
                }else{
                    jsonObject = this.triggerService.createTrigger(dto);
                }
                if(jsonObject.getString("triggerids") != null){
                    JSONArray jsonArray = JSONArray.parseArray(jsonObject.getString("triggerids"));
                    if(jsonArray.size() > 0){
                        Integer triggerids = jsonArray.getInteger(0);
                        Map params = new HashMap();
                        params.put("ip", ip);
                        List<NetworkElement> networkElements = this.networkElementService.selectObjByMap(params);
                        if(networkElements.size() > 0){
                            NetworkElement networkElement = networkElements.get(0);
                            String fluxs = networkElement.getFlux();
                            Map flux = new HashMap();
                            if(fluxs != null && !fluxs.equals("")){
                                flux = JSONObject.parseObject(fluxs, Map.class);
                            }
                            flux.put(interfaceName, triggerids + "&" + val);
                            networkElement.setFlux(JSONObject.toJSONString(flux));
                            this.networkElementService.update(networkElement);
                        }
                    }
                }else{
                    return ResponseUtil.badArgument(jsonObject.getString("data"));
                }
            }
        }
        return ResponseUtil.ok();
    }
//
//    @ApiOperation("创建触发器")
//    @RequestMapping("/create")
//    public Object create(@RequestBody TriggerDTO dto){
//        if(dto.getInterfaceName() != null && !dto.getInterfaceName().equals("")){
//            dto.setDescription(dto.getInterfaceName() + " :UP/DOWN");
//        }
//        if(dto.getIp() != null && !dto.getIndex().equals("")){
//            dto.setExpression("last(/" +
//                    dto.getIp() +
//                    "/net.if.status[ifOperStatus." +
//                    dto.getIndex() +
//                    "])=2 and\n" +
//                    "last(/" +
//                    dto.getIp() +
//                    "/net.if.status[ifOperStatus." +
//                    dto.getIndex() +
//                    "],#1)<>last(/" +
//                    dto.getIp() +
//                    "/net.if.status[ifOperStatus." +
//                    dto.getIndex() +
//                    "],#2)<>0");
//            dto.setRecovery_expression("last(/" +
//                    dto.getIp() +
//                    "/net.if.status[ifOperStatus." +
//                    dto.getIndex() +
//                    "])<>2");
//        }
//        dto.setPriority(0);
//        dto.setRecovery_mode(1);
//
//        Map map = new HashMap();
//        map.put("tag", "objalarm");
//        map.put("value", "intfacestatus");
//        List list = new ArrayList();
//        dto.setTags(list);
////        dto.setCorrelation_tag("objalarm:intfacestatus");
//        String interfaceName = dto.getInterfaceName();
//        String ip = dto.getIp();
//        dto.setIp(null);
//        dto.setIndex(null);
//        dto.setInterfaceName(null);
//        JSONObject jsonObject = this.triggerService.createTrigger(dto); //triggerids
//        if(jsonObject.getString("triggerids") != null){
//            JSONArray jsonArray = JSONArray.parseArray(jsonObject.getString("triggerids"));
//            if(jsonArray.size() > 0){
//                Integer triggerids = jsonArray.getInteger(0);
//                Map params = new HashMap();
//                params.put("ip", ip);
//                List<NetworkElement> networkElements = this.networkElementService.selectObjByMap(params);
//                if(networkElements.size() > 0){
//                    NetworkElement networkElement = networkElements.get(0);
//                    String interfaceNames = networkElement.getInterfaceNames();
//                    Map ports = JSONObject.parseObject(interfaceNames, Map.class);
//                    ports.put(interfaceName, triggerids);
//                    networkElement.setInterfaceNames(JSONObject.toJSONString(ports));
//                    this.networkElementService.update(networkElement);
//                }
//            }
//        }
//        return ResponseUtil.ok();
//    }


    @RequestMapping("/delete/flux")
    public Object delete2(@RequestBody TriggerDTO dto){
        Map params = new HashMap();
        params.put("ip", dto.getIp());
        List<NetworkElement> networkElements = this.networkElementService.selectObjByMap(params);
        if(networkElements.size() > 0){
            NetworkElement networkElement = networkElements.get(0);
            String flux = networkElement.getFlux();
            Map<String, String> fluxs = JSONObject.parseObject(flux, Map.class);
            List<Integer> triggerids = new ArrayList<>();
            for(Map.Entry<String, String> entry : fluxs.entrySet()){
                for (Object interfaceName : dto.getInterfaceNames()) {
                    if(interfaceName.equals(entry.getKey())){
                        String[] value = entry.getValue().split("&");
                        triggerids.add(Integer.parseInt(value[0]));
                    }
                }
            }
            if(triggerids.size() > 0){
                for (Integer triggerid : triggerids) {
                    TriggerDTO trigger = new TriggerDTO();
                    trigger.setTriggerid(triggerid);
                    JSONObject jsonObject = this.triggerService.deleteTrigger(trigger);
                    if(jsonObject.getString("triggerids") != null){
                        JSONArray jsonArray = JSONArray.parseArray(jsonObject.getString("triggerids"));
                        if(jsonArray.size() > 0){
                            Integer id = jsonArray.getInteger(0);
                            params.clear();
                            params.put("ip", dto.getIp());
                            List<NetworkElement> nes = this.networkElementService.selectObjByMap(params);
                            if(nes.size() > 0){
                                NetworkElement ne = nes.get(0);
                                String names = ne.getFlux();
                                Map<String, String> ports2 = JSONObject.parseObject(names, Map.class);
//                                for (Map.Entry<String, String> entry : ports2.entrySet()){
//                                    String[] value = entry.getValue().split("&");
//                                    if(Integer.parseInt(value[0]) == id){
//                                        ports2.remove(entry.getKey());
//                                    }
//                                }
                                Iterator var2 = ports2.entrySet().iterator();
                                while(var2.hasNext()) {
                                    Map.Entry<String, String> entry = (Map.Entry)var2.next();
                                    String[] value = entry.getValue().split("&");
                                    if(Integer.parseInt(value[0]) == id){
//                                        ports2.remove(entry.getKey());
                                        var2.remove();//迭代器删除,不报错
                                    }

                                }
                                // 判断是否存在数据，没有数据就设置为空
//                                if(){ }
                                networkElement.setFlux(JSONObject.toJSONString(ports2));
                                this.networkElementService.update(networkElement);
                            }
                        }
                    }else{
                        return ResponseUtil.badArgument(jsonObject.getString("data"));
                    }
                }

            }
        }
        return ResponseUtil.ok();
    }

    @RequestMapping("/delete")
    public Object delete(@RequestBody TriggerDTO dto){
        Map params = new HashMap();
        params.put("ip", dto.getIp());
        List<NetworkElement> networkElements = this.networkElementService.selectObjByMap(params);
        if(networkElements.size() > 0){
            NetworkElement networkElement = networkElements.get(0);
            String port = networkElement.getInterfaceNames();
            Map<String, Integer> ports = JSONObject.parseObject(port, Map.class);
            List<Integer> triggerids = new ArrayList<>();
            for (String key : ports.keySet()){
                for (Object interfaceName : dto.getInterfaceNames()) {
                    if(interfaceName.equals(key)){
                        triggerids.add(ports.get(key));
                    }
                }
            }
            if(triggerids.size() > 0){
                for (Integer triggerid : triggerids) {
                    TriggerDTO trigger = new TriggerDTO();
                    trigger.setTriggerid(triggerid);
                    JSONObject jsonObject = this.triggerService.deleteTrigger(trigger);
                    if(jsonObject.getString("triggerids") != null){
                        JSONArray jsonArray = JSONArray.parseArray(jsonObject.getString("triggerids"));
                        if(jsonArray.size() > 0){
                            Integer id = jsonArray.getInteger(0);
                            params.clear();
                            params.put("ip", dto.getIp());
                            List<NetworkElement> nes = this.networkElementService.selectObjByMap(params);
                            if(nes.size() > 0){
                                NetworkElement ne = nes.get(0);
                                String names = ne.getInterfaceNames();
                                Map<String, Integer> ports2 = JSONObject.parseObject(names, Map.class);
//                                for (Map.Entry<String, Integer> entry : ports2.entrySet()){
////                                    if(entry.getValue().equals(id)){
////                                        ports2.remove(entry.getKey());
////                                    }
////                                }
                                Iterator var2 = ports2.entrySet().iterator();
                                while(var2.hasNext()) {
                                    Map.Entry<String, Integer> entry = (Map.Entry)var2.next();
                                    if(entry.getValue().equals(id)){
                                        var2.remove();//迭代器删除,不报错
                                    }
                                }
                                // 判断是否存在数据，没有数据就设置为空
//                                if(){ }
                                networkElement.setInterfaceNames(JSONObject.toJSONString(ports2));
                                this.networkElementService.update(networkElement);
                            }
                        }
                    }else{
                        return ResponseUtil.badArgument(jsonObject.getString("data"));
                    }
                }

            }
        }
        return ResponseUtil.ok();
    }
}
