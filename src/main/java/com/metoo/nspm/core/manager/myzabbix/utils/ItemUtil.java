package com.metoo.nspm.core.manager.myzabbix.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostInterfaceService;
import com.metoo.nspm.core.service.api.zabbix.ZabbixItemService;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.core.utils.network.IpV4Util;
import com.github.pagehelper.util.StringUtil;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class ItemUtil {

    @Autowired
    private IpV4Util ipV4Util;
    @Autowired
    private ZabbixItemService zabbixItemService;
    @Autowired
    private ZabbixHostInterfaceService zabbixHostInterfaceService;

    public static Map packaging(String tag, Object value, int operator){
        Map map = new HashMap();
        map.put("tag", tag);
        map.put("value", value);
        map.put("operator", operator);
        return map;
    }

    public List<Map> parseItemq(String ip, List<String> ips){
        // 获取所有路由信息
        JSONArray routs = this.zabbixItemService.getItemRout(ip);
        if(routs != null && routs.size() > 0){
            List<Map> list = new ArrayList();
            for (Object object : routs){
                JSONObject rout = (JSONObject) JSON.toJSON(object);
                String name = rout.getString("name");
                String lastvalue = rout.getString("lastvalue");
                String error = rout.getString("error");
                if(StringUtil.isEmpty(name) || StringUtil.isEmpty(lastvalue) || !StringUtil.isEmpty(error)){
                    continue;
                }
                // 解析tag
                Map map = new HashMap();
                JSONArray tags = JSONArray.parseArray(rout.getString("tags"));
                if(tags.size() > 0){
                    for(Object obj : tags){
                        map.put("cost", lastvalue);
                        JSONObject tag = (JSONObject) JSON.toJSON(obj);
                        if(tag.getString("tag").equals("routedest")){
                            map.put("routedest", tag.getString("value"));
                        }
                        if(tag.getString("tag").equals("routemask")){
                            map.put("routemask", tag.getString("value"));
                        }
                        if(tag.getString("tag").equals("routemetric")){
                            map.put("routemetric", tag.getString("value"));
                        }
                        if(tag.getString("tag").equals("routenexthop")){
                            String nexthop = tag.getString("value");
                            String ip_segment = nexthop.substring(0, nexthop.indexOf("."));
                            if(ip_segment.equals("127")){
                                map.put("flags", "D");
                            }else if(ips.contains(nexthop)){
                                map.put("flags", "D");
                            }else{
                                map.put("flags", "RD");
                            }
                            map.put("routenexthop", tag.getString("value"));
                        }
                        if(tag.getString("tag").equals("routeproto")){
                            map.put("routeproto", tag.getString("value"));
                        }
                        if(tag.getString("tag").equals("routeifindex")){
                            String sequence = tag.getString("value");
                            // 根据标签获取interface
                            JSONArray interfaces = this.zabbixItemService.getItemInterfacesByIndex(ip, Integer.parseInt(sequence));
                            if(interfaces != null && interfaces.size() > 0){
                                for (Object inf : interfaces){
                                    JSONObject item = JSONObject.parseObject(inf.toString());
                                    JSONArray interface_tags = JSONArray.parseArray(item.getString("tags"));
                                    if (interface_tags != null && interface_tags.size() > 0) {
                                        for (Object t : interface_tags) {
                                            JSONObject interface_tag = JSONObject.parseObject(t.toString());
                                            if (interface_tag.getString("tag").equals("ifname")) {
                                                map.put("interface_name", interface_tag.getString("value"));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

//                Map map = this.parseRout(ip, name, lastvalue, ips);
                if(map != null && !map.isEmpty()){
                    list.add(map);
                }
            }
            return list;
        }
        return null;
    }

    /**
     * 获取Zabbix路由item
     * @param ip
     * @return
     */
    public List<Map<String, String>> getRoutItems(String ip){
        // 获取所有路由信息
        JSONArray routs = this.zabbixItemService.getItemRout(ip);
        if(routs != null && routs.size() > 0){
            List<Map<String, String>> list = new ArrayList();
            for (Object object : routs){
                JSONObject rout = (JSONObject) JSON.toJSON(object);
                String name = rout.getString("name");
                String lastvalue = rout.getString("lastvalue");
                String error = rout.getString("error");
                if(StringUtil.isEmpty(name) || StringUtil.isEmpty(lastvalue) || !StringUtil.isEmpty(error)){
                   continue;
                }
                // 解析tag
                Map map = new HashMap();
                JSONArray tags = JSONArray.parseArray(rout.getString("tags"));
                if(tags.size() > 0){
                    for(Object obj : tags){
                        // 获取 interface
//                        map.put("interfaceName", lastvalue);
                        JSONObject tag = (JSONObject) JSON.toJSON(obj);
                        if(tag.getString("tag").equals("routedest")){
                            map.put("destination", IpUtil.ipConvertDec(tag.getString("value")));
                        }
                        if(tag.getString("tag").equals("routemask")){
                            map.put("mask", tag.getString("value"));
                        }
                        if(tag.getString("tag").equals("routemetric")){
                            map.put("routemetric", tag.getString("value"));
                        }
                        if(tag.getString("tag").equals("routenexthop")){
                            map.put("nextHop", IpUtil.ipConvertDec(tag.getString("value")));
                        }
                        if(tag.getString("tag").equals("routeproto")){
                            map.put("proto", tag.getString("value"));
                        }
                        if(tag.getString("tag").equals("routeifindex")){
                            String sequence = tag.getString("value");
                            map.put("interfaceName", sequence);
                            // 根据标签获取 interface
                            JSONArray interfaces = this.zabbixItemService.getItemInterfacesByIndex(ip, Integer.parseInt(sequence));
                            if(interfaces != null && interfaces.size() > 0){
                                for (Object inf : interfaces){
                                    JSONObject item = JSONObject.parseObject(inf.toString());
                                    JSONArray interface_tags = JSONArray.parseArray(item.getString("tags"));
                                    if (interface_tags != null && interface_tags.size() > 0) {
                                        for (Object t : interface_tags) {
                                            JSONObject interface_tag = JSONObject.parseObject(t.toString());
                                            if (interface_tag.getString("tag").equals("ifname")) {
                                                map.put("interfaceName", interface_tag.getString("value"));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if(map.get("proto").equals("2")){
                        map.put("nextHop", "");
                        map.put("flags", "D");
                    }
                }

//                Map map = this.parseRout(ip, name, lastvalue, ips);
                if(map != null && !map.isEmpty()){
                    list.add(map);
                }
            }
            return list;
        }
        return null;
    }

    public Map parseRout(String ip, String name, String lastvalue, List<String> ips){
        Integer sequence = null;
        Map map = new HashMap();
            int nfirst = name.indexOf(" ");
            int first = name.indexOf(" ");
            int last = name.indexOf(".");
            last = name.indexOf(".", last + 1);
            last = name.indexOf(".", last + 1);
            last = name.indexOf(".", last + 1);
            String destination = name.substring(first + 1, last);
            System.out.println(destination);
            first = last + 1;
            last = name.indexOf(".", last + 1);
            last = name.indexOf(".", last + 1);
            last = name.indexOf(".", last + 1);
            last = name.indexOf(".", last + 1);
            String destination_mask = name.substring(first, last);
            if(StringUtils.isNotEmpty(destination_mask)){
                destination_mask = String.valueOf(this.ipV4Util.getMaskBitByMask(destination_mask));
            }
            System.out.println(destination_mask);
            last = name.indexOf(".", last + 1);
            first = last + 1;
            last = name.indexOf(" ", nfirst + 1);
            String nexthop = name.substring(first, last);
            System.out.println(nexthop);
            first = last + 1;
            last = name.indexOf(" ", last + 1);
            String index = name.substring(first, last);
            sequence = Integer.parseInt(index);
            System.out.println(index);
            first = last + 1;
            last = name.indexOf(":", last);
            String proto = name.substring(first, last);
            System.out.println(proto);

            map.put("destination", destination);
            map.put("destination_mask", destination_mask);
            map.put("nexthop", nexthop);
            map.put("index", sequence);
            map.put("proto", proto);
            map.put("cost", lastvalue);
            // 验证当前 nexthop 是否存在本地网段中
            // 获取本地网段列表
            String ip_segment = nexthop.substring(0, nexthop.indexOf("."));
            if(ip_segment.equals("127")){
                map.put("flags", "D");
            }else if(ips.contains(nexthop)){
                map.put("flags", "D");
            }else{
                map.put("flags", "RD");
            }
        if(sequence != null){
            // 获取接口名
            // 根据标签获取interface
            JSONArray interfaces = this.zabbixItemService.getItemInterfacesByIndex(ip, sequence);
            if(interfaces != null && interfaces.size() > 0){
                for (Object obj : interfaces){
                    JSONObject item = JSONObject.parseObject(obj.toString());
                    JSONArray tags = JSONArray.parseArray(item.getString("tags"));
                    if (tags != null && tags.size() > 0) {
                        for (Object t : tags) {
                            JSONObject tag = JSONObject.parseObject(t.toString());
                            if (tag.getString("tag").equals("ifname")) {
                                map.put("interface_name", tag.getString("value"));
                            }
                        }
                    }
                }
            }
        }
        return map != null ? map : null;
    }

    // 补全
    public static String strLenComplement(String str, int length){
        if(str == null){
            str = "";
        }
        // 计算原字符串所占长度，规定中文占两个，其他占一个
        int strlen = 0;
        for(int i = 0; i < str.length(); i++){
            if(isChinese(str.charAt(i))) {
                strlen = strlen + 2;
            }else{
                strlen = strlen  + 1;
            }
        }
        if(strlen >= length){
            return str;
        }
        // 计算要补充空格长度
        int remain = length - strlen;
        for (int i = 0; i < remain; i++) {
            str = str + " ";
        }

        return str;
    }

    // 根据Unicode编码完美的判断中文汉字和符号
    public static boolean isChinese(char c){
        Character.UnicodeBlock ub = Character.UnicodeBlock.of(c);
        if(ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS
                || ub == Character.UnicodeBlock.CJK_COMPATIBILITY_IDEOGRAPHS
                || ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A
                || ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_B
                || ub == Character.UnicodeBlock.CJK_SYMBOLS_AND_PUNCTUATION
                || ub == Character.UnicodeBlock.HALFWIDTH_AND_FULLWIDTH_FORMS
                || ub == Character.UnicodeBlock.GENERAL_PUNCTUATION){
            return true;
        }
        return false;
    }

    // 根据IP查询本地网络地址列表
    public List<String> getHostIps(String ip){
        List tags = new ArrayList();
        Map map = new HashMap();
        map.put("obj", "ipaddress");
        tags.add(map);
        List output = new ArrayList();
        output.add("tag");
        output.add("value");
        JSONArray arrays = this.zabbixItemService.getItemByIpAndTag(ip, tags, output);
        return null;
    }

    /**
     * 根据索引获取 InterfeceName
     * @param ip
     * @param index
     * @return
     */
    public String getInterfaceName(String ip, String index){
        JSONArray interfaces = this.zabbixItemService.getItemInterfacesTagByIndex(ip, index);
        if(interfaces != null && interfaces.size() > 0){
            for (Object inf : interfaces){
                JSONObject item = JSONObject.parseObject(inf.toString());
                JSONArray interface_tags = JSONArray.parseArray(item.getString("tags"));
                if (interface_tags != null && interface_tags.size() > 0) {
                    for (Object t : interface_tags) {
                        JSONObject interface_tag = JSONObject.parseObject(t.toString());
                        if (interface_tag.getString("tag").equals("ifname")) {
                            return interface_tag.getString("value");
                        }
                    }
                }
            }
        }
        return null;
    }

    public String getInterfaceNameBy(String ip, int sequence){
        JSONArray interfaces = this.zabbixItemService.getItemIfIndexByIndexTag(ip);
        if(interfaces != null && interfaces.size() > 0){
            int num = 1;
            for (Object inf : interfaces){
                if(num != sequence){
                    num++;
                    continue;
                }
                JSONObject item = JSONObject.parseObject(inf.toString());
                JSONArray interface_tags = JSONArray.parseArray(item.getString("tags"));
                if (interface_tags != null && interface_tags.size() > 0) {
                    for (Object t : interface_tags) {
                        JSONObject interface_tag = JSONObject.parseObject(t.toString());
                        if (interface_tag.getString("tag").equals("ifname")) {
                            return interface_tag.getString("value");
                        }
                    }
                }
            }
        }
        return null;
    }

    public Map<String, String> getInterfaceDetail(String ip, String index){
        JSONArray interfaces = this.zabbixItemService.getItemInterfacesTagByIndex(ip, index);
        if(interfaces != null && interfaces.size() > 0){
            for (Object inf : interfaces){
                JSONObject item = JSONObject.parseObject(inf.toString());
                JSONArray tags = JSONArray.parseArray(item.getString("tags"));
                if (tags != null && tags.size() > 0) {
                    Map<String, String> map = new HashMap();
                    for (Object t : tags) {
                        JSONObject tag = JSONObject.parseObject(t.toString());
                        if (tag.getString("tag").equals("ifname")) {
                            map.put("interfaceName", tag.getString("value"));
                        }
                        if (tag.getString("tag").equals("ifmac")) {
                            map.put("mac", tag.getString("value"));
                        }
                    }
                    return map;
                }
            }
        }
        return null;
    }


    /**
     * 校验主机是否可用
     * @param ip
     * @return
     */
    public boolean verifyHostIsAvailable(String ip){
        JSONObject hostInterface = zabbixHostInterfaceService.getHostInterfaceInfo(ip);
        if(hostInterface.getString("available") != null){
            if(hostInterface.getString("available").equals("1")){
                return true;
            }
        }
        return false;
    }

}
