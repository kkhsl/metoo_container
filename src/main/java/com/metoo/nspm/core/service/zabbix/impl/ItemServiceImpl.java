package com.metoo.nspm.core.service.zabbix.impl;

import com.metoo.nspm.core.manager.myzabbix.utils.ItemUtil;
import com.metoo.nspm.core.mapper.zabbix.ItemMapper;
import com.metoo.nspm.core.mapper.zabbix.ItemTagMapper;
import com.metoo.nspm.core.service.api.zabbix.ZabbixItemService;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.service.topo.ITopoNodeService;
import com.metoo.nspm.core.service.zabbix.ItemService;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.core.utils.network.IpV4Util;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.entity.zabbix.Item;
import com.metoo.nspm.entity.zabbix.ItemTag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
//@Transactional
public class ItemServiceImpl implements ItemService {

    @Autowired
    private ItemMapper itemMapper;
    @Autowired
    private ItemTagMapper itemTagMapper;
    @Autowired
    private ITopoNodeService topoNodeService;
    @Autowired
    private IpDetailService ipDetailService;
    @Autowired
    private ZabbixItemService zabbixItemService;
    @Autowired
    private ItemUtil itemUtil;
    @Autowired
    private IArpService arpService;
    @Autowired
    private IArpTempService arpTempService;
    @Autowired
    private IMacTempService macTempService;
    @Autowired
    private IRoutTempService routTempService;
    @Autowired
    private IIPAddressTempService ipAddressTempService;

//    public static void main(String[] args) {
//        String value = "4.10.25.65.162.32.2.0.0.1.4.10.25.248.18";
//        String[] str = value.split("\\.");
//        StringBuffer dest = new StringBuffer();
//        String mask = "";
//        StringBuffer nexthop = new StringBuffer();
//        Scanner sc = new Scanner(value).useDelimiter("\\.");
//        for(int i = 1; i<= str.length; i ++){
//            if(2 <= i && i <= 4){
//                dest.append(sc.next()).append(".");
//            }else if(i == 5){
//                dest.append(sc.next());
//            }else if(i == 6){
//                mask  = sc.next();
//            }else if(12 <= i && i <= 14){
//                nexthop.append(sc.next()).append(".");
//            }else if(i == 15){
//                nexthop.append(sc.next());
//            }else{
//                sc.next();
//            }
//        }
//        System.out.println(dest.toString());
//        System.out.println(mask);
//        System.out.println(nexthop.toString());
//    }

    @Override
    public void gatherArpItem(Date time) {
        Map params = new HashMap();
        List<Map> ipList = this.topoNodeService.queryNetworkElement();
        List<String> ips = new ArrayList();// 初始化Ip集合（采集IP,记录IP在线时长以及使用率）
        if (ipList != null && ipList.size() > 0) {
            this.arpTempService.truncateTable();
            for (Map map : ipList) {
                // 采集Arp(Zabbix)
                String deviveName = map.get("deviceName").toString();
                String deviceType = map.get("deviceType").toString();
                String ip = map.get("ip").toString();
                String uuid = map.get("uuid").toString();

                params.put("ip", ip);
                params.put("tag", "arphillstone");
                params.put("index", "ifindex");
                params.put("tag_relevance", "ifbasic");
                params.put("index_relevance", "ifindex");
                params.put("name_relevance", "ifname");
                List<Item> itemTagArpList = itemMapper.selectItemTagByMap(params);
                if(itemTagArpList.size() > 0){
                    for (Item item : itemTagArpList) {
                        List<ItemTag> tags = item.getItemTags();
                        ArpTemp arpTemp = new ArpTemp();
                        arpTemp.setDeviceName(deviveName);
                        arpTemp.setDeviceType(deviceType);
                        arpTemp.setUuid(uuid);
                        arpTemp.setDeviceIp(ip);
                        arpTemp.setTag("S");
                        // ip使用率
                        IpDetail ipDetail = new IpDetail();
                        if (tags != null && tags.size() > 0) {
                            for (ItemTag tag : tags) {
                                String value = tag.getValue();
                                if (tag.getTag().equals("ip")) {
                                    arpTemp.setIp(IpUtil.ipConvertDec(value));
                                    ipDetail.setIp(IpUtil.ipConvertDec(value));
                                    ips.add(IpUtil.ipConvertDec(value));
                                }
                                if (tag.getTag().equals("mac")) {
                                    arpTemp.setMac(value);
                                    ipDetail.setMac(value);
                                }
                                if (tag.getTag().equals("ifindex")) {
                                    // 1, 获取ifbasic最小minIndex, minIndex + (ifindex - 1)
                                    //2, 根据新获取的index获取ifbasic的端口名
                                    // 1,
                                    ItemTag itemTag = this.itemTagMapper.selectItemTagMinIfIndex(ip);
                                    String ifindex = itemTag.getValue();
                                    int index = 0;
                                    if(ifindex != null){
                                        index = Integer.parseInt(ifindex);
                                        index = index + (Integer.parseInt(value) - 1);
                                        params.clear();
                                        params.put("ip", ip);
                                        params.put("ifindex", index);
                                        ItemTag itemTag2 = this.itemTagMapper.selectItemTagIfNameByIndex(params);
                                        arpTemp.setIndex(String.valueOf(index));
                                        arpTemp.setInterfaceName(itemTag2.getValue());
                                    }
                                }
                            }
                            // 保存Arp条目
                            if (arpTemp.getIp() != null && !arpTemp.getIp().equals("")) {
                                params.clear();
                                params.put("ip", arpTemp.getIp());
                                params.put("deviceName", arpTemp.getDeviceName());
                                params.put("interfaceName", arpTemp.getInterfaceName());
                                List<ArpTemp> localArps = arpTempService.selectObjByMap(params);
                                if (localArps.size() == 0) {
                                    arpTemp.setAddTime(time);
                                    arpTempService.save(arpTemp);
                                }
                                // 记录ip使用率
                                IpDetail existingIp = ipDetailService.selectObjByIp(ipDetail.getIp());
                                if (existingIp == null) {
                                    ipDetail.setDeviceName(deviveName);
                                    ipDetailService.save(ipDetail);
                                }
                            }
                        }
                    }

                }
                if(itemTagArpList.size() <= 0){
                    params.put("ip", ip);
                    params.put("tag", "arp");
                    params.put("index", "ifindex");
                    params.put("tag_relevance", "ifbasic");
                    params.put("index_relevance", "ifindex");
                    params.put("name_relevance", "ifname");
                    List<Item> itemTagList = itemMapper.gatherItemByTag(params);
                    if (itemTagList.size() > 0) {
                        for (Item item : itemTagList) {
                            List<ItemTag> tags = item.getItemTags();
                            ArpTemp arpTemp = new ArpTemp();
                            arpTemp.setDeviceName(deviveName);
                            arpTemp.setDeviceType(deviceType);
                            arpTemp.setUuid(uuid);
                            arpTemp.setDeviceIp(ip);
                            arpTemp.setTag("S");
                            // ip使用率
                            IpDetail ipDetail = new IpDetail();
                            if (tags != null && tags.size() > 0) {
                                for (ItemTag tag : tags) {
                                    String value = tag.getValue();
                                    if (tag.getTag().equals("ip")) {
                                        arpTemp.setIp(IpUtil.ipConvertDec(value));
                                        ipDetail.setIp(IpUtil.ipConvertDec(value));
                                        ips.add(IpUtil.ipConvertDec(value));
                                    }
                                    if (tag.getTag().equals("mac")) {
                                        arpTemp.setMac(value);
                                        ipDetail.setMac(value);
                                    }
                                    if (tag.getTag().equals("ifindex")) {
                                        if(value != null){
                                            arpTemp.setInterfaceName(tag.getName());
                                            arpTemp.setIndex(value);
                                        }else{
                                            //
                                            switch (value){
                                                case "1":
                                            }
                                        }
                                    }
                                }
                                // 保存Arp条目
                                if (arpTemp.getIp() != null && !arpTemp.getIp().equals("")) {
                                    params.clear();
                                    params.put("ip", arpTemp.getIp());
                                    params.put("deviceName", arpTemp.getDeviceName());
                                    params.put("interfaceName", arpTemp.getInterfaceName());
                                    List<ArpTemp> localArps = arpTempService.selectObjByMap(params);
                                    if (localArps.size() == 0) {
                                        arpTemp.setAddTime(time);
                                        arpTempService.save(arpTemp);
                                    }
                                    // 记录ip使用率
                                    IpDetail existingIp = ipDetailService.selectObjByIp(ipDetail.getIp());
                                    if (existingIp == null) {
                                        ipDetail.setDeviceName(deviveName);
                                        ipDetailService.save(ipDetail);
                                    }
                                }
                            }
                        }
                    }
                }

            }
        }
            // 补全(默认标记为L)
            for (Map map : ipList) {
                // 采集Arp(Zabbix)
                String deviveName = map.get("deviceName").toString();
                String deviceType = map.get("deviceType").toString();
                String ip = map.get("ip").toString();
                String uuid = map.get("uuid").toString();
                params.put("ip", ip);
                params.put("tag", "ifipaddr");
                params.put("tag_relevance", "ifbasic");
                params.put("index", "ifindex");
                params.put("index_relevance", "ifindex");
                params.put("name_relevance", "ifname");
                params.put("mac_relevance", "ifmac");
                List<Item> ipaddressItem = itemMapper.gatherItemByTagAndIndex(params);
                if (ipaddressItem.size() > 0) {
                    for (Item item : ipaddressItem) {
                        List<ItemTag> tags = item.getItemTags();
                        ArpTemp arpTemp = new ArpTemp();
                        arpTemp.setDeviceName(deviveName);
                        arpTemp.setDeviceType(deviceType);
                        arpTemp.setUuid(uuid);
                        arpTemp.setDeviceIp(ip);
                        if (tags != null && tags.size() > 0) {
                            for (ItemTag tag : tags) {
                                String value = tag.getValue();
                                if (tag.getTag().equals("ipaddr")) {
                                    arpTemp.setIp(IpUtil.ipConvertDec(value));
                                }
                                if (tag.getTag().equals("mask")) {
                                    arpTemp.setMask(value);
                                }
//                                if (tag.getTag().equals("ifindex")) {
//                                    if(tag.getName() != null && !tag.getName().equals("")){
//                                        String[] values = tag.getName().split("%");
//                                        if(values.length == 2){
//                                            arpTemp.setInterfaceName(values[0]);
//                                            arpTemp.setMac(values[1]);
//                                        }
//                                    }
//                                }
                                if (tag.getTag().equals("ifindex")) {
                                    arpTemp.setInterfaceName(tag.getName());
                                    arpTemp.setMac(tag.getMac());
                                    arpTemp.setIndex(value);
                                }
                            }
                            // 查询arp
                            if(arpTemp.getIp() != null && !arpTemp.getIp().equals("")){
                                params.clear();
                                params.put("ip", arpTemp.getIp());
                                params.put("deviceName", arpTemp.getDeviceName());
                                params.put("interfaceName", arpTemp.getInterfaceName());
                                List<ArpTemp> localArps = arpTempService.selectObjByMap(params);
                                if (localArps.size() == 0
                                        && arpTemp.getInterfaceName() != null
                                        && !arpTemp.getInterfaceName().equals("")) {
                                    arpTemp.setTag("L");
                                    arpTemp.setAddTime(time);
                                    arpTempService.save(arpTemp);
                                } else if (localArps.size() > 0) {
                                    ArpTemp local = localArps.get(0);
                                    local.setTag("L");
                                    local.setMask(arpTemp.getMask());
                                    arpTempService.update(local);
                                }
                            }

                        }
                    }
                }
            }
            // 计算ip使用率
            params.clear();
            if (ips.size() > 0) {
                Set set = new HashSet();
                set.addAll(ips);
                ips.clear();
                ips.addAll(set);
                IpDetail init = ipDetailService.selectObjByIp("0.0.0.0");
                init.setTime(init.getTime() + 1);
                ipDetailService.update(init);
                // 总时长
                params.put("ipId", init.getId());
                params.put("arpIpList", ips);
                List<IpDetail> IpDetails = ipDetailService.selectObjByMap(params);
                IpDetails.forEach((item) -> {
                    item.setOnline(true);
                    item.setTime(item.getTime() + 1);
                    int initTime = init.getTime() + 1;
                    float num = (float) item.getTime() / initTime;
                    int usage = Math.round(num * 100);
                    item.setUsage(usage);
                    ipDetailService.update(item);
                });
                params.clear();
                params.put("notIpList", ips);
                List<IpDetail> ipDetails = ipDetailService.selectObjByMap(params);
                ipDetails.forEach((item) -> {
                    item.setOnline(false);
                    ipDetailService.update(item);
                });
            }

    }


    @Override
    public void gatherMacItem(Date time){
        List<Map> ipList = this.topoNodeService.queryNetworkElement();
        if (ipList != null && ipList.size() > 0) {
            Map params = new HashMap();
            this.macTempService.truncateTable();
            for (Map map : ipList) {
                String deviveName = map.get("deviceName").toString();
                String deviceType = map.get("deviceType").toString();
                String ip = map.get("ip").toString();
                String uuid = map.get("uuid").toString();

                // 采集 interface Mac
                params.clear();
                params.put("ip", ip);
                params.put("tag", "ifbasic");
                params.put("tag_relevance", "ifbasic");
                params.put("index", "ifindex");
                params.put("index_relevance", "ifindex");
                params.put("name_relevance", "ifname");
                List<Item> itemIfBasicTagList = itemMapper.gatherItemByTag(params);
                if (itemIfBasicTagList.size() > 0) {
                    for (Item item : itemIfBasicTagList) {
                        List<ItemTag> tags = item.getItemTags();
                        MacTemp macTemp = new MacTemp();
                        macTemp.setDeviceName(deviveName);
                        macTemp.setDeviceType(deviceType);
                        macTemp.setUuid(uuid);
                        macTemp.setDeviceIp(ip);
                        if (tags != null && tags.size() > 0) {
                            for (ItemTag tag : tags) {
                                String value = tag.getValue();
                                if (tag.getTag().equals("ifmac")) {
//                                    格式化mac
                                    if(!value.contains(":")){
                                        value = value.trim().replaceAll(" ", ":");
                                    }
                                    macTemp.setMac(value);
                                    params.clear();
                                    params.put("mac", value);
                                    List<Arp> arps = arpService.selectObjByMap(params);
                                    if (arps.size() > 0) {
                                        Arp arp = arps.get(0);
                                        macTemp.setIp(arp.getIp());
                                        macTemp.setIpAddress(arp.getIpAddress());
                                    }
                                }
                                if (tag.getTag().equals("ifname")) {
                                    macTemp.setInterfaceName(value);
                                }
                                if (tag.getTag().equals("ifindex")) {
                                    macTemp.setIndex(value);
                                }
                            }
                            // 保存Mac条目
                            if (macTemp.getInterfaceName() != null && !macTemp.getInterfaceName().equals("")
                                    && macTemp.getMac() != null && !macTemp.getMac().equals("{#MAC}")
                                    && !macTemp.getMac().equals("{#IFMAC}")) {
                                params.clear();
                                params.put("deviceName", macTemp.getDeviceName());
                                params.put("interfaceName", macTemp.getInterfaceName());
                                params.put("mac", macTemp.getMac());
                                List<MacTemp> macs = macTempService.selectByMap(params);
                                if (macs.size() == 0) {
                                    macTemp.setTag("L");
                                    if (macTemp.getMac().contains("0:0:5e:0")) {
                                        macTemp.setTag("LV");
                                    }
                                    macTemp.setAddTime(time);
                                    macTempService.save(macTemp);
                                }
                            }
                        }
                    }
                }

                // 采集Mac(Zabbix)
                params.clear();
                params.put("ip", ip);
                params.put("tag", "mac");
                params.put("index", "portindex");
                params.put("tag_relevance", "ifbasic");
                params.put("index_relevance", "ifindex");
                params.put("name_relevance", "ifname");
                List<Item> itemTagList = itemMapper.gatherItemByTag(params);
                // Begin(item)
                if (itemTagList.size() > 0) {
                    for (Item item : itemTagList) {
                        List<ItemTag> tags = item.getItemTags();
                        MacTemp macTemp = new MacTemp();
                        macTemp.setDeviceName(deviveName);
                        macTemp.setDeviceType(deviceType);
                        macTemp.setUuid(uuid);
                        macTemp.setDeviceIp(ip);
                        if (tags != null && tags.size() > 0) {
                            for (ItemTag tag : tags) {
                                String value = tag.getValue();
                                if (tag.getTag().equals("mac")) {
//                                    格式化mac
                                    if(!value.contains(":")){
                                        value = value.trim().replaceAll(" ", ":");
                                    }
                                    macTemp.setMac(value);
                                    params.clear();
                                    params.put("mac", value);
                                    List<Arp> arps = arpService.selectObjByMap(params);
                                    if(arps.size() > 0){
                                        Arp arp = arps.get(0);
                                        macTemp.setIp(arp.getIp());
                                        macTemp.setIpAddress(arp.getIpAddress());
                                    }
                                }
                                if (tag.getTag().equals("portindex")) {
                                    macTemp.setInterfaceName(tag.getName());
                                    macTemp.setIndex(value);
                                }
                                if (tag.getTag().equals("vlan")) {
                                    macTemp.setVlan(value);
                                }
                            }
                            // 保存Mac条目
                            if(macTemp.getInterfaceName() != null && !macTemp.getInterfaceName().equals("")
                                    && macTemp.getMac() != null && !macTemp.getMac().equals("{#MAC}")
                                    && !macTemp.getMac().equals("{#IFMAC}")){
                                params.clear();
                                params.put("deviceName", macTemp.getDeviceName());
                                params.put("interfaceName", macTemp.getInterfaceName());
                                params.put("mac", macTemp.getMac());
                                List<MacTemp> macs = macTempService.selectByMap(params);
                                if(macs.size() == 0){
                                    if(macTemp.getMac().contains("0:0:5e:0")){
                                        macTemp.setTag("LV");
                                    }
                                    macTemp.setAddTime(time);
                                    macTempService.save(macTemp);
                                }
                            }
                        }
                    }
                }
            }
        }
    }


    @Override
    public void gatherRouteItem(Date time) {
        List<Map> ipList = this.topoNodeService.queryNetworkElement();
        if(ipList != null && ipList.size() > 0) {
            this.routTempService.truncateTable();
            for (Map map : ipList) {
                String deviceName = map.get("deviceName").toString();
                String ip = map.get("ip").toString();
                String uuid = map.get("uuid").toString();
                Map params = new HashMap();
                params.clear();
                params.put("ip", ip);
                params.put("tag", "routecisco");
                params.put("index", "routeifindex");
                params.put("tag_relevance", "ifbasic");
                params.put("index_relevance", "ifindex");
                params.put("name_relevance", "ifname");
                List<Item> itemRouteciscoTagList = this.itemMapper.gatherItemByTag(params);
                if(itemRouteciscoTagList.size() > 0){
                    for (Item item : itemRouteciscoTagList) {
                        List<ItemTag> tags = item.getItemTags();
                        RouteTemp routTemp = new RouteTemp();
                        routTemp.setDeviceName(deviceName);
                        routTemp.setDeviceUuid(uuid);
                        routTemp.setAddTime(time);
                        if (tags != null && tags.size() > 0) {
                            String routedest = "";
                            for (ItemTag tag : tags) {
                                String value = tag.getValue();
                                if(tag.getTag().equals("route")){
                                    String[] str = value.split("\\.");
                                    StringBuffer dest = new StringBuffer();
                                    String mask = "";
                                    StringBuffer nexthop = new StringBuffer();
                                    Scanner sc = new Scanner(value).useDelimiter("\\.");
                                    for(int i = 1; i<= str.length; i ++){
                                        if(2 <= i && i <= 4){
                                            dest.append(sc.next()).append(".");
                                        }else if(i == 5){
                                            dest.append(sc.next());
                                        }else if(i == 6){
                                            mask  = sc.next();
                                        }else if(12 <= i && i <= 14){
                                            nexthop.append(sc.next()).append(".");
                                        }else if(i == 15){
                                            nexthop.append(sc.next());
                                        }else{
                                            sc.next();
                                        }
                                    }
                                    routedest = dest.toString();
                                    routTemp.setDestination(IpUtil.ipConvertDec(dest.toString()));
                                    routTemp.setMask(mask);
                                    routTemp.setMaskBit(IpV4Util.getMaskBitByMask(mask));
                                    routTemp.setNextHop(IpUtil.ipConvertDec(nexthop.toString()));
                                }
                                if(tag.getTag().equals("routemetric")){
                                    routTemp.setCost(value);
                                }
                                if(tag.getTag().equals("routeproto")){
                                    String v = "";
                                    switch (value){
                                        case "2":
                                            v = "direct";
                                            break;
                                        case "3":
                                            v = "static";
                                            break;
                                        case "8":
                                            v = "rip";
                                            break;
                                        case "9":
                                            v = "isis";
                                            break;
                                        case "13":
                                            v = "ospf";
                                            break;
                                        case "14":
                                            v = "bgp";
                                            break;
                                    }
                                    routTemp.setProto(value);
                                }
                                if(tag.getTag().equals("routeifindex")){
                                    routTemp.setInterfaceName(tag.getName());
                                }
                            }
                            if(routTemp.getProto().equals("2")){
                                map.put("nextHop", "");
                                map.put("flags", "D");
                            }
                            if(!routTemp.getCost().equals("{#RTMETRIC}") && !routTemp.getProto().equals("0")
                                    && !routedest.equals("127.0.0.1")){
                                this.routTempService.save(routTemp);
                            }
                        }
                    }
                }
                if(itemRouteciscoTagList.size() <= 0){
                    params.clear();
                    params.put("ip", ip);
                    params.put("tag", "route");
                    params.put("index", "routeifindex");
                    params.put("tag_relevance", "ifbasic");
                    params.put("index_relevance", "ifindex");
                    params.put("name_relevance", "ifname");
                    List<Item> itemRouteTagList = this.itemMapper.gatherItemByTag(params);
                    if (itemRouteTagList.size() > 0) {
                        for (Item item : itemRouteTagList) {
                            List<ItemTag> tags = item.getItemTags();
                            RouteTemp routTemp = new RouteTemp();
                            routTemp.setDeviceName(deviceName);
                            routTemp.setDeviceUuid(uuid);
                            routTemp.setAddTime(time);
                            String routedest = "";
                           if (tags != null && tags.size() > 0) {
                                for (ItemTag tag : tags) {
                                    String value = tag.getValue();
                                    if(tag.getTag().equals("routedest")){
                                        routedest = value;
                                        routTemp.setDestination(IpUtil.ipConvertDec(value));
                                    }
                                    if(tag.getTag().equals("routemask")){
                                        routTemp.setMask(value);
                                        routTemp.setMaskBit(IpV4Util.getMaskBitByMask(value));
                                    }
                                    if(tag.getTag().equals("routemetric")){
                                        routTemp.setCost(value);
                                    }
                                    if(tag.getTag().equals("routenexthop")){
                                        routTemp.setNextHop(IpUtil.ipConvertDec(value));
                                    }
                                    if(tag.getTag().equals("routeproto")){
                                        String v = "";
                                        switch (value){
                                            case "2":
                                                v = "direct";
                                                break;
                                            case "3":
                                                v = "static";
                                                break;
                                            case "8":
                                                v = "rip";
                                                break;
                                            case "9":
                                                v = "isis";
                                                break;
                                            case "13":
                                                v = "ospf";
                                                break;
                                            case "14":
                                                v = "bgp";
                                                break;
                                        }
                                        routTemp.setProto(v);
                                    }
                                    if(tag.getTag().equals("routeifindex")){
                                        routTemp.setInterfaceName(tag.getName());
                                    }
                                }
                                if(routTemp.getProto().equals("2")){
                                    map.put("nextHop", "");
                                    map.put("flags", "D");
                                }
                                if(!routTemp.getCost().equals("{#RTMETRIC}") && !routTemp.getProto().equals("0")
                                        && !routedest.equals("127.0.0.1")){
                                    this.routTempService.save(routTemp);
                                }
                            }
                        }
                    }
                }

            }
        }
    }

    @Override
    public void gatherIpaddressItem(Date time) {
        List<Map> ipList = this.topoNodeService.queryNetworkElement();
        if(ipList != null && ipList.size() > 0) {
            this.ipAddressTempService.truncateTable();
            for (Map map : ipList) {
                String deviceName = map.get("deviceName").toString();
                String ip = map.get("ip").toString();
                String uuid = map.get("uuid").toString();
                Map params = new HashMap();
                params.clear();
                params.put("ip", ip);
                params.put("tag", "ifipaddr");
                params.put("index", "ifindex");
                params.put("tag_relevance", "ifbasic");
                params.put("index_relevance", "ifindex");
                params.put("name_relevance", "ifname");
                List<Item> itemRouteTagList = this.itemMapper.gatherItemByTag(params);
                if (itemRouteTagList.size() > 0) {
                    for (Item item : itemRouteTagList) {
                        List<ItemTag> tags = item.getItemTags();
                        if (tags != null && tags.size() > 0) {
                            IpAddressTemp ipAddressTemp = new IpAddressTemp();
                            ipAddressTemp.setDeviceName(deviceName);
                            ipAddressTemp.setDeviceUuid(uuid);
                            ipAddressTemp.setAddTime(time);
                            for (ItemTag tag : tags) {
                                String value = tag.getValue();
                                if (tag.getTag().equals("ipaddr")) {
                                    ipAddressTemp.setIp(IpUtil.ipConvertDec(value));
                                }
                                if (tag.getTag().equals("mask")) {
                                    ipAddressTemp.setMask(IpUtil.getBitMask(value));
                                }
                                if (tag.getTag().equals("ifindex")) {
                                    ipAddressTemp.setInterfaceName(tag.getName());
                                }
                            }
                            if(ipAddressTemp.getIp() != null && !ipAddressTemp.getIp().equals("127.0.0.1")){
                                params.clear();
//                                params.put("deviceName", ipAddressTemp.getDeviceName());
//                                params.put("interfaceName", ipAddressTemp.getInterfaceName());
                                params.put("ip", ipAddressTemp.getIp());
                                List<IpAddressTemp> ips = this.ipAddressTempService.selectObjByMap(params);
                                if(ips.size() == 0){
                                    ipAddressTemp.setAddTime(time);
                                    this.ipAddressTempService.save(ipAddressTemp);
                                }else{
                                    // 比较uuid是否相同，更新uuid
                                    IpAddressTemp ipAddress1 = ips.get(0);
                                    if(!ipAddress1.getDeviceUuid().equals(uuid)){
                                        this.ipAddressTempService.update(ipAddressTemp);
                                    }
                                }
                            }

                        }
                    }
                }
            }
        }
    }

    @Override
    public void gatherProblemItem(Date time) {
        List<Map> ipList = this.topoNodeService.queryNetworkElement();
        if(ipList != null && ipList.size() > 0) {
            this.ipAddressTempService.truncateTable();
            for (Map map : ipList) {
                String deviceName = map.get("deviceName").toString();
                String ip = map.get("ip").toString();
                String uuid = map.get("uuid").toString();
                Map params = new HashMap();
                params.clear();
                params.put("ip", ip);
                params.put("tag", "");
                params.put("index", "ifindex");
                params.put("tag_relevance", "ifbasic");
                params.put("index_relevance", "ifindex");
                params.put("name_relevance", "ifname");
                List<Item> itemRouteTagList = this.itemMapper.gatherItemByTag(params);
                if (itemRouteTagList.size() > 0) {
                    for (Item item : itemRouteTagList) {
                        List<ItemTag> tags = item.getItemTags();
                        if (tags != null && tags.size() > 0) {
                            ProblemTemp problemTemp = new ProblemTemp();
                            problemTemp.setDeviceName(deviceName);
                            problemTemp.setUuid(uuid);
                            problemTemp.setAddTime(time);
                            for (ItemTag tag : tags) {

                            }
                        }
                    }
                }
            }
        }
    }

    @Override
    public List<Item> selectTagByMap(Map params) {
        List<Item> items = this.itemMapper.selectTagByMap(params);
        // 解析items
        return items;
    }

    @Override
    public List<Item> selectItemTagByMap(Map params) {
        return this.itemMapper.selectItemTagByMap(params);
    }

    @Override
    public void testTransactional() throws ArithmeticException{
//        ArpTemp arpTemp = new ArpTemp();
//        arpTemp.setDeviceName("a");
//        this.arpTempService.save(arpTemp);

        try {
            int i = 1 / 0;// 捕获异常后，此处不在回滚
        } catch (Exception e) {
            e.printStackTrace();
        }

        int i = 1 / 0;// 捕获异常后，此处不在回滚

        Arp arp = new Arp();
        arp.setDeviceName("a");
        this.arpService.save(arp);
    }

    @Override
    public List<Item> selectNameObjByIndex(String index) {
        return this.itemMapper.selectNameObjByIndex(index);
    }

}
