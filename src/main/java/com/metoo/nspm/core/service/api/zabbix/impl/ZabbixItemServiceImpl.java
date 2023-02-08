package com.metoo.nspm.core.service.api.zabbix.impl;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.myzabbix.utils.ItemUtil;
import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostService;
import com.metoo.nspm.core.service.api.zabbix.ZabbixItemService;
import com.metoo.nspm.core.service.nspm.IArpTempService;
import com.metoo.nspm.core.service.nspm.IMacService;
import com.metoo.nspm.core.service.nspm.IMacTempService;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.core.utils.network.IpV4Util;
import com.metoo.nspm.dto.zabbix.HostDTO;
import com.metoo.nspm.dto.zabbix.ItemDTO;
import com.metoo.nspm.entity.nspm.ArpTemp;
import com.metoo.nspm.entity.nspm.IpAddress;
import com.metoo.nspm.entity.nspm.MacTemp;
import io.github.hengyunabc.zabbix.api.Request;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class ZabbixItemServiceImpl implements ZabbixItemService {

    @Autowired
    private ZabbixApiUtil zabbixApiUtil;
    @Autowired
    private IpV4Util ipV4Util;
    @Autowired
    private ZabbixHostService zabbixHostService;
    @Autowired
    private IArpTempService arpTempService;
    @Autowired
    private IMacService macService;
    @Autowired
    private IMacTempService macTempService;

    @Override
    public JSONObject getItem(ItemDTO dto) {
        Request request = this.zabbixApiUtil.parseParam(dto, "item.get");
        return zabbixApiUtil.call(request);
    }

    @Override
    public JSONArray getItemById(Integer id) {
        ItemDTO itemDto = new ItemDTO();
        itemDto.setItemids(Arrays.asList(id));
        JSONObject items = this.getItem(itemDto);
        if(items.get("result") != null) {
            JSONArray itemArray = JSONArray.parseArray(items.getString("result"));
            return itemArray;
        }
        return new JSONArray();
    }

    public JSONArray getItemAndTagByHostId(String ip, List tags, List output){
        String hostid = this.zabbixHostService.getHostId(ip);
        if(hostid != null){
            ItemDTO itemDto = new ItemDTO();
            itemDto.setHostids(Arrays.asList(hostid));
            Map filterMap = new HashMap();
            itemDto.setFilter(filterMap);
            itemDto.setMonitored(true);
            if(tags != null){
                itemDto.setTags(tags);
            }
            if(output != null){
                itemDto.setOutput(output);
            }
            itemDto.setSelectTags("extend");
            JSONObject items = this.getItem(itemDto);
            if(items.get("result") != null) {
                JSONArray itemArray = JSONArray.parseArray(items.getString("result"));
                return itemArray;
            }
        }
        return null;
    }

    public JSONArray getItemAndTagByIp(String ip, List tags, List output){
        ItemDTO itemDto = new ItemDTO();
        Map filterMap = new HashMap();
        filterMap.put("ip",ip);
        itemDto.setFilter(filterMap);
        itemDto.setMonitored(true);
        if(tags != null){
            itemDto.setTags(tags);
        }
        if(output != null){
            itemDto.setOutput(output);
        }
        itemDto.setSelectTags("extend");
        JSONObject items = this.getItem(itemDto);
        if(items.get("result") != null) {
            JSONArray itemArray = JSONArray.parseArray(items.getString("result"));
            return itemArray;
        }
        return null;
    }

    @Override
    public JSONArray getItemByIpAndTag(String ip, List tags, List output){
        if(StringUtils.isNotEmpty(ip)){
            HostDTO dto = new HostDTO();
            Map map = new HashMap();
            map.put("ip", Arrays.asList(ip));
            dto.setFilter(map);
            dto.setMonitored(true);
            Object object = this.zabbixHostService.getHost(dto);
            JSONObject jsonObject = JSONObject.parseObject(object.toString());
            if(jsonObject.get("result") != null){
                JSONArray arrays = JSONArray.parseArray(jsonObject.getString("result"));
                if(arrays.size() > 0){
                    JSONObject host = JSONObject.parseObject(arrays.get(0).toString());
                    String hostid = host.getString("hostid");
                    if(hostid != null){
                        ItemDTO itemDto = new ItemDTO();
                        itemDto.setHostids(Arrays.asList(hostid));
                        Map filterMap = new HashMap();
                        itemDto.setFilter(filterMap);
                        itemDto.setMonitored(true);
                        itemDto.setTags(tags);
                        itemDto.setOutput(output);
                        itemDto.setSelectTags("extend");
                        Object itemObejct = this.getItem(itemDto);
                        JSONObject itemJSON = JSONObject.parseObject(itemObejct.toString());
                        if(itemJSON.get("result") != null) {
                            JSONArray itemArray = JSONArray.parseArray(itemJSON.getString("result"));
                            return itemArray;
                        }

                    }
                }
            }
        }
        return null;
    }

    @Override
    public JSONArray getItemIpAddress(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifipaddr", 1));
            tags.add(ItemUtil.packaging("ipaddr", "127.0.0.1", 3));
            return this.getItemAndTagByHostId(ip, tags, null);
        }
        return null;
    }

    @Override
    public JSONArray getItemIpAddressTag(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifipaddr", 1));
            tags.add(ItemUtil.packaging("ipaddr", "127.0.0.1", 3));
            List output = new ArrayList();
            output.add("tag");
            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, output);
        }
        return null;
    }

    @Override
    public JSONArray getItemIpAddressTagByIndex(String ip, Integer index) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifipaddr", 1));
            tags.add(ItemUtil.packaging("ipaddr", "127.0.0.1", 3));
            if(index != null){
                tags.add(ItemUtil.packaging("ifindex", index, 1));
            }
            List output = new ArrayList();
            output.add("tag");
            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, output);
        }
        return null;
    }


    @Override
    public JSONArray getItemOperationalTagByIndex(String ip, Integer index) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifoperstatus", 1));
            if(index != null){
                tags.add(ItemUtil.packaging("ifindex", index, 1));
            }
            List output = new ArrayList();
            output.add("tag");
            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, output);
        }
        return null;
    }

    @Override
    public JSONArray getItemsByIpAndTags(String ip, List<String> list) {
        if(list.size() > 0){
            List tags = new ArrayList();
            for(String tag : list){
                tags.add(ItemUtil.packaging("obj", tag, 1));
            }

//            List output = new ArrayList();
//            output.add("tag");
//            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, null);
        }
        return null;
    }

    @Override
    public JSONArray getItemTags(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifbasic", 1));
            tags.add(ItemUtil.packaging("obj", "ifsent", 1));
            tags.add(ItemUtil.packaging("obj", "ifspeed", 1));
            tags.add(ItemUtil.packaging("obj", "ifreceived", 1));

//            List output = new ArrayList();
//            output.add("tag");
//            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, null);
        }
        return null;
    }

    @Override
    public JSONArray getItemMac(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "mac", 1));
            return this.getItemAndTagByHostId(ip, tags, null);
        }
        return null;
    }


    @Override
    public JSONArray getItemMacTag(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "mac", 1));
            List output = new ArrayList();
            output.add("tag");
            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, output);
        }
        return null;
    }

    @Override
    public JSONArray getItemSpeedTag(String ip, Integer index) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifspeed", 1));
            tags.add(ItemUtil.packaging("ifindex", index, 1));
            return this.getItemAndTagByHostId(ip, tags, null);
        }
        return null;
    }

    @Override
    public JSONArray getItemArpTag(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "arp", 1));
//            List output = new ArrayList();
//            output.add("tag");
//            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, null);
        }
        return null;
    }

    @Override
    public JSONArray getItemInterfacesByIndex(String ip, Integer index) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifbasic", 1));
            if(index != null){
                tags.add(ItemUtil.packaging("ifindex", index, 1));
            }
            return this.getItemAndTagByHostId(ip, tags, null);
        }
        return null;
    }

    @Override
    public JSONArray getItemInterfacesTagByIndex(String ip, String index) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifbasic", 1));
            if(index != null){
                tags.add(ItemUtil.packaging("ifindex", index, 1));
            }
            List output = new ArrayList();
            output.add("tag");
            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, output);
        }
        return null;
    }

    @Override
    public JSONArray getItemIfIndexByIndexTag(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifindex", 1));
            List output = new ArrayList();
            output.add("tag");
            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, output);
        }
        return null;
    }

    @Override
    public JSONArray getItemInterfacesTag(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifbasic", 1));
            List output = new ArrayList();
            output.add("tag");
            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, output);
        }
        return null;
    }

    @Override
    public JSONArray getItemInterfaces(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "ifbasic", 1));
            return this.getItemAndTagByHostId(ip, tags, null);
        }
        return null;
    }

    @Override
    public JSONArray getItemRout(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "route", 1));
            return this.getItemAndTagByHostId(ip, tags, null);
        }
        return null;
    }

    @Override
    public JSONArray getItemRoutTag(String ip) {
        if(ip != null){
            List tags = new ArrayList();
            tags.add(ItemUtil.packaging("obj", "route", 1));
            List output = new ArrayList();
            output.add("tag");
            output.add("value");
            return this.getItemAndTagByHostId(ip, tags, output);
        }
        return null;
    }


    @Override
    public Map<String, List<Object>> ipAddressCombing(JSONArray items) {
        if(items.size() == 0){
            return null;
        }
        Map<String, Integer> map = new HashMap();
        List<Integer> masks = new ArrayList();
        for (Object array : items){
            JSONObject item = (JSONObject) JSON.toJSON(array);
            JSONArray tags = JSONArray.parseArray(item.getString("tags"));
            if(tags != null && tags.size() > 0){
                String ip = null;
                String mask = item.getString("mask");
                for (Object t : tags){
                    JSONObject tag = JSONObject.parseObject(t.toString());
                    if(tag.getString("tag").equals("ipaddr")){
                        ip = tag.getString("value");
                    }
                    if(tag.getString("tag").equals("mask")){
                        mask = tag.getString("value");
                    }
                }
                int bitMask = ipV4Util.getMaskBitByMask(mask);// 获取掩码位
                Map networkMap = IpUtil.getNetworkIp(ip, mask);
                map.put(networkMap.get("network").toString(), bitMask);
                masks.add(bitMask);
            }
        }
        // 第二步：提取最短掩码，生成上级网段
        HashSet set = new HashSet(masks);
        masks.clear();
        masks.addAll(set);
        Collections.sort(masks);
        Integer firstMask = masks.get(0);// 最短掩码
        Map<String, Integer> firstMap = new HashMap();
        Map<String, Integer> otherMap = new HashMap();
        for (Map.Entry<String, Integer> entry : map.entrySet()){
            if(entry.getValue() == firstMask){
                firstMap.put(entry.getKey(), entry.getValue());
            }else{
                otherMap.put(entry.getKey(), entry.getValue());
            }
        }
        // 提取
        Map<String, List<Object>> parentMap = new HashMap<>();
        for (Map.Entry<String, Integer> entry : firstMap.entrySet()) {
            Integer mask = entry.getValue();
            String ip = entry.getKey();
            Integer parentMask = null;
            if (mask > 24) {
                parentMask = 24;
            } else if (24 >= mask && mask > 16) {
                parentMask = 16;
            } else if (16 >= mask && mask > 8) {
                parentMask = 8;
            }
            String parentIp = this.getParentIp(ip, parentMask);
            parentIp = parentIp + "/" + parentMask;
            if (parentMap.get(parentIp) == null) {
                List<Object> list = new ArrayList<>();
                list.add(ip + "/" + mask);
                parentMap.put(parentIp, list);
            } else {
                List<Object> list = parentMap.get(parentIp);
                list.add(ip + "/" + mask);
            }
        }
//        遍历
        Map parentSegment = new HashMap();
        for (Map.Entry entry1 : parentMap.entrySet()) {
            String parentIpMask = (String) entry1.getKey();
            String parentIp = null;
            Integer parentMask = null;
            int sequence = parentIpMask.indexOf("/");
            parentIp = parentIpMask.substring(0, sequence);
            parentMask = Integer.parseInt(parentIpMask.substring(sequence + 1));
            int parentIndex = 0;
            String parentIpSeggment = null;
            if (parentMask == 24) {
                parentIndex =  parentIpMask.indexOf(".");
                parentIndex =  parentIpMask.indexOf(".", parentIndex + 1);
                parentIndex =  parentIpMask.indexOf(".", parentIndex + 1);
            } else if (parentMask == 16) {
                parentIndex =  parentIpMask.indexOf(".");
                parentIndex =  parentIpMask.indexOf(".", parentIndex + 1);
            } else if (parentMask == 8) {
                parentIndex =  parentIpMask.indexOf(".");
            }
            parentIpSeggment = parentIpMask.substring(0, parentIndex);
            parentSegment.put(parentIpSeggment, parentIp);
        }

        // 判断是否属于第一级
        for (Map.Entry<String, Integer> entry : otherMap.entrySet()) {
            Integer mask = entry.getValue();
            String ip = entry.getKey();
            String ip_segment = null;
            int index = 0;
            if (mask > 24) {
                index =  ip.indexOf(".");
                index =  ip.indexOf(".", index + 1);
                index =  ip.indexOf(".", index + 1);
            } else if (24 >= mask && mask > 16) {
                index =  ip.indexOf(".");
                index =  ip.indexOf(".", index + 1);
            } else if (16 >= mask && mask > 8) {
                index =  ip.indexOf(".");
            }
            ip_segment = ip.substring(0, index);
            if(parentSegment.get(ip_segment) != null){
                List<Object> list = parentMap.get(parentSegment.get(ip_segment));
                list.add(ip + "/" + mask);
            }else{
                Integer parentMask = null;
                if (mask > 24) {
                    parentMask = 24;
                } else if (24 >= mask && mask > 16) {
                    parentMask = 16;
                } else if (16 >= mask && mask > 8) {
                    parentMask = 8;
                }
                String parentIp = this.getParentIp(ip, parentMask);
                parentIp = parentIp + "/" + parentMask;
                List<Object> list = new ArrayList<>();
                list.add(ip + "/" + mask);
                parentMap.put(parentIp, list);
                parentSegment.put(ip_segment, parentIp);
            }
        }
        // 遍历二级ip，生成上级Ip
        if(parentMap.size() > 1){
            Map<String, List<Object>> parent = this.getShorMask(parentMap);
            if(parent != null && parent.size() > 0){
                return parent;
            }
        }else{

        }
        return parentMap;
    }

    @Override
    public Map<String, List<Object>> ipAddressCombingByDB(List<IpAddress> ipList) {
        if(ipList.size() == 0){
            return null;
        }
        Map<String, Integer> map = new HashMap();
        List<Integer> masks = new ArrayList();
        for (IpAddress ipAddress : ipList){
            String ip = ipAddress.getIp();
            Integer mask = Integer.parseInt(ipAddress.getMask());
            String mask2 = IpUtil.bitMaskConvertMask(mask);
            Map networkMap = IpUtil.getNetworkIp(ip, mask2);
            map.put(networkMap.get("network").toString(), mask);
            masks.add(mask);
        }
        // 第二步：提取最短掩码，生成上级网段
        HashSet set = new HashSet(masks);
        masks.clear();
        masks.addAll(set);
        Collections.sort(masks);
        Integer firstMask = masks.get(0);// 最短掩码
        Map<String, Integer> firstMap = new HashMap();
        Map<String, Integer> otherMap = new HashMap();
        for (Map.Entry<String, Integer> entry : map.entrySet()){
            if(entry.getValue() == firstMask){
                firstMap.put(entry.getKey(), entry.getValue());
            }else{
                otherMap.put(entry.getKey(), entry.getValue());
            }
        }
        // 提取
        Map<String, List<Object>> parentMap = new HashMap<>();
        for (Map.Entry<String, Integer> entry : firstMap.entrySet()) {
            Integer mask = entry.getValue();
            String ip = entry.getKey();
            Integer parentMask = null;
            if (mask > 24) {
                parentMask = 24;
            } else if (24 >= mask && mask > 16) {
                parentMask = 16;
            } else if (16 >= mask && mask > 8) {
                parentMask = 8;
            }
            String parentIp = this.getParentIp(ip, parentMask);
            parentIp = parentIp + "/" + parentMask;
            if (parentMap.get(parentIp) == null) {
                List<Object> list = new ArrayList<>();
                list.add(ip + "/" + mask);
                parentMap.put(parentIp, list);
            } else {
                List<Object> list = parentMap.get(parentIp);
                list.add(ip + "/" + mask);
            }
        }
//        遍历
        Map parentSegment = new HashMap();
        for (Map.Entry entry1 : parentMap.entrySet()) {
            String parentIpMask = (String) entry1.getKey();
            String parentIp = null;
            Integer parentMask = null;
            int sequence = parentIpMask.indexOf("/");
            parentIp = parentIpMask.substring(0, sequence);
            parentMask = Integer.parseInt(parentIpMask.substring(sequence + 1));
            int parentIndex = 0;
            String parentIpSeggment = null;
            if (parentMask == 24) {
                parentIndex =  parentIpMask.indexOf(".");
                parentIndex =  parentIpMask.indexOf(".", parentIndex + 1);
                parentIndex =  parentIpMask.indexOf(".", parentIndex + 1);
            } else if (parentMask == 16) {
                parentIndex =  parentIpMask.indexOf(".");
                parentIndex =  parentIpMask.indexOf(".", parentIndex + 1);
            } else if (parentMask == 8) {
                parentIndex =  parentIpMask.indexOf(".");
            }
            parentIpSeggment = parentIpMask.substring(0, parentIndex);
            parentSegment.put(parentIpSeggment, parentIp);
        }

        // 判断是否属于第一级
        for (Map.Entry<String, Integer> entry : otherMap.entrySet()) {
            Integer mask = entry.getValue();
            String ip = entry.getKey();
            String ip_segment = null;
            int index = 0;
            if (mask > 24) {
                index =  ip.indexOf(".");
                index =  ip.indexOf(".", index + 1);
                index =  ip.indexOf(".", index + 1);
            } else if (24 >= mask && mask > 16) {
                index =  ip.indexOf(".");
                index =  ip.indexOf(".", index + 1);
            } else if (16 >= mask && mask > 8) {
                index =  ip.indexOf(".");
            }
            ip_segment = ip.substring(0, index);
            if(parentSegment.get(ip_segment) != null){
                List<Object> list = parentMap.get(parentSegment.get(ip_segment));
                list.add(ip + "/" + mask);
            }else{
                Integer parentMask = null;
                if (mask > 24) {
                    parentMask = 24;
                } else if (24 >= mask && mask > 16) {
                    parentMask = 16;
                } else if (16 >= mask && mask > 8) {
                    parentMask = 8;
                }
                String parentIp = this.getParentIp(ip, parentMask);
                parentIp = parentIp + "/" + parentMask;
                List<Object> list = new ArrayList<>();
                list.add(ip + "/" + mask);
                parentMap.put(parentIp, list);
                parentSegment.put(ip_segment, parentIp);
            }
        }
        // 遍历二级ip，生成上级Ip
        if(parentMap.size() > 1){
            Map<String, List<Object>> parent = this.getShorMask(parentMap);
            if(parent != null && parent.size() > 0){
                return parent;
            }
        }else{

        }
        return parentMap;
    }

    @Override
    public void arpTag() {
        // 检测 0:0:5e:0
        Map params = new HashMap();
        params.put("like", 0);
        List<ArpTemp> arps = this.arpTempService.selectObjByMap(params);
        for (ArpTemp arp : arps) {
            arp.setTag("V");
            this.arpTempService.update(arp);
        }
        // 标记LS
        params.clear();
        params.put("tag", "L");
        params.put("count", 2);
        List<ArpTemp> ls = this.arpTempService.arpTag(params);
        ls.forEach(item -> {
            item.setTag("LS");
            this.arpTempService.update(item);
        });

        // 对端设备查询(开启三个线程？检索仅有两台mac的，检索拥有多个mac的,检索对端设备)
        // 1-0：arp条目默认设置为S(除本接口arp条目外)
        // 1-1: 端口仅有1条arp条目（除本接口条目外），此条目标记为U（Unsure）
        // 单台设备（标记'U'）
        List<ArpTemp> tagArp = this.arpTempService.selectObjByDistinct();
        if(tagArp.size() > 0){
            for (ArpTemp arp : tagArp) {
                params.clear();
                params.put("count", 1);
                params.put("interfaceName", arp.getInterfaceName());
                params.put("deviceName", arp.getDeviceName());
                List<ArpTemp> arpList = this.arpTempService.selectObjByInterface(params);
                for (ArpTemp obj : arpList) {
                    if (!obj.getTag().equals("L")) {
                        obj.setTag("U");
                        this.arpTempService.update(obj);
                    }
                }
            }
        }

        // 单台设备（标记'US'）
        params.clear();
        params.put("tag1", "L");
        params.put("tag2", "LS");
        params.put("count", 2);
        List<ArpTemp> arpList = this.arpTempService.arpTag(params);
        arpList.forEach(item -> {
            item.setTag("US");
            this.arpTempService.update(item);
        });
        /**
         * 同一个arp条目，在全网中有U和L两个标记，则将U改为E（ Equipment），
         * 并对对端设备和接口字段进行标记（L标记条目的设备和接口）
         */
        // 多台设备 标记‘E’在全网中有U和L两个标记，将U改为E(Equipment) 不加LS
        params.clear();
        params.put("tagL", "L");
        params.put("tagU", "U");
        List<ArpTemp> ulAapList = this.arpTempService.selectOppositeByMap(params);
        for (ArpTemp arp : ulAapList) {
            arp.setTag("E");
            this.arpTempService.update(arp);
        }
        // 多台设备 标记‘EM’ 全网存在US和LS两个标记，US改EM
        params.clear();
        params.put("tag1", "US");
        params.put("tag2", "LS");
        params.put("count", 1);// 可优化
        List<ArpTemp> emArps = this.arpTempService.selectSubquery(params);
        for (ArpTemp arpTemp : emArps) {
            arpTemp.setTag("EM");
            params.clear();
            params.put("tag", "LS");
            params.put("mac", arpTemp.getMac());
            params.put("ip", arpTemp.getIp());
            List<ArpTemp> remotes = this.arpTempService.selectObjByMap(params);
            if (remotes.size() > 0) {
                ArpTemp remote = remotes.get(0);
                arpTemp.setRemoteDevice(remote.getDeviceName());
                arpTemp.setRemoteInterface(remote.getInterfaceName());
                arpTemp.setRemoteUuid(remote.getUuid());
                arpTemp.setRemoteDeviceType(remote.getDeviceType());
                arpTemp.setRemoteIp(remote.getIp());
                arpTemp.setRemoteDeviceIp(remote.getDeviceIp());
            }
            this.arpTempService.update(arpTemp);
        }
        params.clear(); // 全网“L”
        params.put("tag", "L");
        params.put("tagLS", "LS");
        List<ArpTemp> larps = this.arpTempService.selectObjByGroupMap(params);
        // 获取全网主机ip
        Map<Map<String, String>, List> hostIpAddresses = new HashMap();
        for (ArpTemp arp : larps) {
            if(arp.getIp() != null){
                Map key = new HashMap();
                key.put("ip", arp.getIp());
                key.put("deviceName", arp.getDeviceName());
                key.put("interfaceName", arp.getInterfaceName());
                key.put("deviceType", arp.getDeviceType());
                key.put("uuid", arp.getUuid());
                key.put("deviceIp", arp.getDeviceIp());
                hostIpAddresses.put(key, null/*this.ipV4Util.getHost(arp.getIp(), arp.getMask())*/);
            }
        }

        /**
         * 同一个arp条目，在全网中有S和L两个标记，则将S改为ES（Equipment Share），
         * 并对对端设备和接口字段进行标记（L标记条目的设备和接口）
         * selectOppositeByMap
         */
        params.clear(); // 1-3 同一arp条目，在全网有“S”和“L”两个标记，“S”改为“ES”
        params.put("tag", "S");
        List<ArpTemp> arpS = this.arpTempService.selectObjByGroupMap(params);
        for (ArpTemp arpTemp : arpS) {
            for (Map.Entry<Map<String, String>, List> entry : hostIpAddresses.entrySet()) {
                Map<String, String> remote = entry.getKey();
                if (remote.get("ip").equals(arpTemp.getIp())) {
//                        if (entry.getValue() != null && entry.getValue().contains(arp.getIp())) {
                    arpTemp.setTag("ES");
                    arpTemp.setRemoteDevice(remote.get("deviceName"));
                    arpTemp.setRemoteInterface(remote.get("interfaceName"));
                    arpTemp.setRemoteUuid(remote.get("uuid"));
                    arpTemp.setRemoteDeviceType(remote.get("deviceType"));
                    arpTemp.setRemoteIp(remote.get("ip"));
                    arpTemp.setRemoteDeviceIp(remote.get("deviceIp"));
                    this.arpTempService.update(arpTemp);
//                        }
                }
            }
        }


        // 标记T 同一arp条目在全网只有S标记(没有L)，只在一台设备有S标记则将S改为T
        params.clear();
        params.put("count", 1);
        params.put("tag", "S");
        List<ArpTemp> sArpList = this.arpTempService.selectGroupByHavingMac(params);
        for (ArpTemp s : sArpList) {
            s.setTag("T");
            this.arpTempService.update(s);
        }
        // 同一arp条目在全网只有S标记,在多台设备有S标记则将S改为TS
        params.clear();
        params.put("count", 2);
        List<ArpTemp> tsAapList = this.arpTempService.selectObjByMac(params);
        for (ArpTemp ts : tsAapList) {
            Map distinct = new HashMap();// 查询改mac地址是否存在"L"
            distinct.put("mac", ts.getMac());
            distinct.put("tag", "L");
            List<ArpTemp> arpMac = this.arpTempService.selectObjByMap(distinct);
            if (arpMac.size() == 0) {
                ts.setTag("TS");
                this.arpTempService.update(ts);
            }
        }
    }

    @Override
    public void macTag() {
        // 单台设备 标记’U|S‘
        Map params = new HashMap();
        params.put("u", 1);
        List<MacTemp> umac = this.macTempService.getMacUS(params);
        umac.forEach(item ->{
            item.setTag("U");
            this.macTempService.update(item);
        });
        params.clear();
        params.put("s", 2);
        List<MacTemp> smac = this.macTempService.getMacUS(params);
        smac.forEach(item ->{
            item.setTag("S");
            this.macTempService.update(item);
        });

        // 标记E|UE|UT(优化)
        params.clear();
        params.put("tag", "U");
        List<MacTemp> umacs = this.macTempService.selectByMap(params);
        for (MacTemp obj : umacs){
            params.clear();
            params.put("tag", "L");
            params.put("mac", obj.getMac());
//            params.put("ip", IpUtil.ipConvertDec(obj.getIp()));
            params.put("unDeviceName", obj.getDeviceName());
            List<MacTemp> macs = this.macTempService.selectByMap(params);// 只有一个
            if(macs.size() > 0){
                MacTemp instancce = macs.get(0);
                obj.setTag("E");
                obj.setRemoteDevice(instancce.getDeviceName());
                obj.setRemoteUuid(instancce.getUuid());
                obj.setRemoteInterface(instancce.getInterfaceName());
                obj.setRemoteDeviceIp(instancce.getDeviceIp());
                obj.setRemoteDeviceType(instancce.getDeviceType());
                this.macTempService.update(obj);
                continue;
            }
            params.clear();
            params.put("macId", obj.getId());
            params.put("other", "L");
            params.put("mac", obj.getMac());
            List<MacTemp> macList = this.macTempService.selectByMap(params);
            if(macList.size() > 0){
                obj.setTag("UT");
                this.macTempService.update(obj);
            }else{
                obj.setTag("DT");
                this.macTempService.update(obj);
            }
        }
        // 标记E|RT|UE
        params.clear();
        params.put("tag", "S");
        List<MacTemp> a = this.macTempService.selectByMap(params);
        for (MacTemp obj :  a){
            // 查询arp
            params.clear();
            params.put("tag", "L");
            params.put("mac", obj.getMac());
            params.put("unDeviceName", obj.getDeviceName());
            List<MacTemp> macs = this.macTempService.selectByMap(params);
            if(macs.size() > 0){
                MacTemp instancce = macs.get(0);
                obj.setTag("E");
                obj.setRemoteDevice(instancce.getDeviceName());
                obj.setRemoteUuid(instancce.getUuid());
                obj.setRemoteInterface(instancce.getInterfaceName());
                obj.setRemoteDeviceIp(instancce.getDeviceIp());
                obj.setRemoteDeviceType(instancce.getDeviceType());
                this.macTempService.update(obj);
                continue;
            }
        }
        // 查询剩余S条目
        params.clear();
        params.put("tag", "S");
        List<MacTemp> residueS = this.macTempService.selectByMap(params);
        for (MacTemp obj :  residueS){
            obj.setTag("RT");
            this.macTempService.update(obj);
        }
        // 为DE的条目，查询mac对应的L条目的portindex < 4069标记为DE,记录端口名
        params.clear();
        List<MacTemp> emacs = this.macTempService.groupByObjByMap(params);
        for(MacTemp eobj : emacs){
            params.clear();
            params.put("deviceName", eobj.getDeviceName());
            List<MacTemp> demacs = this.macTempService.groupByObjByMap2(params);
            if(demacs.size() > 0){
                for (MacTemp demac : demacs){
                    params.clear();
                    params.put("deviceName", demac.getDeviceName());
                    params.put("remoteDevice", demac.getRemoteDevice());
                    List<MacTemp> macs = this.macTempService.selectByMap(params);
                    if(macs.size() >= 2){
                        for(MacTemp mac : macs){
                            params.clear();
                            params.put("tag", "L");
                            params.put("device_name", mac.getRemoteDevice());
                            params.put("mac", mac.getMac());
                            List<MacTemp> remoteMacs = this.macTempService.selectByMap(params);
                            for(MacTemp remoteMac : remoteMacs){
                                if(com.metoo.nspm.core.utils.StringUtils.isInteger(remoteMac.getIndex())){
                                    if(remoteMac.getIndex() != null && Integer.parseInt(remoteMac.getIndex()) < 4096){
                                        mac.setTag("DE");
                                        this.macTempService.update(mac);
                                    }
                                    if(remoteMac.getIndex() != null && Integer.parseInt(remoteMac.getIndex()) >= 4096){
                                        mac.setTag("E");
                                        this.macTempService.update(mac);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

        }
        // 标记为E
        params.clear();
        params.put("tag", "E");
        List<MacTemp> emacList = this.macTempService.selectByMap(params);
        if(emacList.size() > 0){
            for(MacTemp mac : emacList){
                params.clear();
                params.put("macId", mac.getId());
                params.put("other", "L");
                params.put("mac", mac.getMac());
                List<MacTemp> macList = this.macTempService.selectByMap(params);
                if(macList.size() == 0){
                    mac.setTag("DE");
                    this.macTempService.update(mac);
                }
            }
        }
        // mac|arp联查
        // 标记为UT且有ip地址的，标记为DT
        params.clear();
        params.put("tag", "S");
        List<MacTemp> macs = this.macTempService.macJoinArp(params);
        macs.forEach(item ->{
            this.macTempService.update(item);
        });
    }

    public Map<String, List<Object>> getShorMask(Map<String, List<Object>> parentMap){
//        String parentIp = null;
        Integer shorMask = 0;
        for (Map.Entry<String, List<Object>> entry : parentMap.entrySet()){
            String ip = entry.getKey();
            int index = ip.indexOf("/");
            int mask = Integer.parseInt(ip.substring(index + 1));
            if(mask > shorMask || shorMask == 0){
                shorMask = mask;
            }
        }
        // 遍历parentMap 获取掩码位等于parentmask网段集合

        Map<String, List<Object>> map = new HashMap<>();

        for (Map.Entry<String, List<Object>> entry : parentMap.entrySet()){
            String ipMask = entry.getKey();
            int index = ipMask.indexOf("/");
            int mask = Integer.parseInt(ipMask.substring(index + 1));
            // 判断当前mask是否等于最短mask
            if(mask != shorMask){
                map.put(ipMask, parentMap.get(ipMask));
            }
        }
        for (Map.Entry<String, List<Object>> entry : parentMap.entrySet()){
            String ipMask = entry.getKey();
            int index = ipMask.indexOf("/");
            int mask = Integer.parseInt(ipMask.substring(index + 1));
            String ip = ipMask.substring(0, index);
            Integer parentMask = null;
            // 判断当前mask是否等于最短mask
            if(mask == shorMask){
                // 同为最低等级mask/创建上级
                if (mask > 24) {
                    parentMask = 24;
                } else if (24 >= mask && mask > 16) {
                    parentMask = 16;
                } else if (16 >= mask && mask > 8) {
                    parentMask = 8;
                }
                // 生成上级网段
                String parentIp = this.getParentIp(ip, parentMask);
                parentIp = parentIp + "/" + parentMask;
                // 比较是否已经存在
                if(parentMap.get(parentIp) != null){

                    List<Object> list = map.get(parentIp);

                    List<Object> childs = parentMap.get(ipMask);

                    Map child = new HashMap();

                    child.put(ipMask, childs);

                    list.add(child);

                    map.put(parentIp, list);

                }else{
                    List<Object> list =  new ArrayList<>();

                    List<Object> childs = parentMap.get(ipMask);

                    Map child = new HashMap();
                    child.put(ipMask, childs);

                    list.add(child);

                    map.put(parentIp, list);
                }
            }
        }
        return map;
    }

    /**
     *
     * @param ip
     * @param mask
     * @return
     */
    public String getParentIp(String ip, Integer mask){
        int index = 0;
        String segment = "";
        if (24 == mask) {
            index =  ip.indexOf(".");
            index =  ip.indexOf(".", index + 1);
            index =  ip.indexOf(".", index + 1);
            segment = ".0";
        } else if (16  == mask) {
            index =  ip.indexOf(".");
            index =  ip.indexOf(".", index + 1);
            segment = ".0.0";
        }else if (8  == mask) {
            index =  ip.indexOf(".");
            segment = ".0.0.0";
        }
        String parentIp = ip.substring(0, index);
        return parentIp + segment;
    }

}
