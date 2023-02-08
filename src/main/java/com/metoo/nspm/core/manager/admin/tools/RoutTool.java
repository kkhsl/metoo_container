package com.metoo.nspm.core.manager.admin.tools;

import com.alibaba.fastjson.JSONArray;
import com.github.pagehelper.util.StringUtil;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.entity.nspm.IpAddress;
import com.metoo.nspm.entity.nspm.Mac;
import com.metoo.nspm.entity.nspm.Route;
import com.metoo.nspm.entity.nspm.RouteTable;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class RoutTool {


    @Autowired
    private IRoutService routService;
    @Autowired
    private IRoutHistoryService routHistoryService;
    @Autowired
    private IRoutTableService routTableService;
    @Autowired
    private IIPAddressService ipAddressServie;
    @Autowired
    private ZabbixSubnetService subnetService;
    @Autowired
    private IMacService macService;
    @Autowired
    private IMacHistoryService macHistoryService;


    /**
     *
     * @param ipAddress 起点设备
     * @param destIp 终点ip
     * @param descMask 终点Mask
     * @return
     */
    public List<IpAddress> generatorRout(IpAddress ipAddress, String destIp, String descMask, Date time) {
        List<IpAddress> ipAddresses = new ArrayList<>();
        if (ipAddress != null) {
            ipAddress.setStatus(0);
            Map params = new HashMap();
            // 查询当前设备在路由表中是否已记录
            params.clear();
            params.put("ip", ipAddress.getIp());
            params.put("mask", ipAddress.getMask());
            params.put("deviceName", ipAddress.getDeviceName());
            params.put("interfaceName", ipAddress.getInterfaceName());
            params.put("mac", ipAddress.getMac());
            List<RouteTable> ipaddressRouts = this.routTableService.selectObjByMap(params);
            RouteTable ipaddressRoutTable = null;
            if(ipaddressRouts.size() > 0) {
                ipaddressRoutTable = ipaddressRouts.get(0);
            }
            Route rout = this.queryRout(destIp, descMask, ipAddress.getDeviceName(), time);// 查询起点路由
//            Map params = IpUtil.getNetworkIp(destIp, descMask);
//            params.put("deviceName", ipAddress.getDeviceName());
//            Route rout = this.routService.selectDestDevice(params);
            if(rout != null){
                params.clear();
                params.put("deviceName", ipAddress.getDeviceName());
                params.put("destination", rout.getDestination());
                params.put("mask", rout.getMask());
                List<Route> nexthops = this.routService.selectNextHopDevice(params);
//              List<Route> nexthops = this.routService.queryDestDevice(params);
                if (nexthops.size() > 0) {
                    outCycle:for (Route nextHop : nexthops) {
                        if(nextHop.getNextHop() != null && !nextHop.getNextHop().equals("")){
                            String nexeIp = nextHop.getNextHop();
                            // 这里使用continue，继续进行下一个nexthop
                            if(nexeIp == null || nexeIp.equals("") || nexeIp.equals("127.0.0.1") || nexeIp.equals("0.0.0.0")){
                                // 不在执行下一跳，为终端设备
                                ipaddressRoutTable.setStatus(3);
                                this.routTableService.update(ipaddressRoutTable);
                                continue;
                            }

                            Map srcmap = IpUtil.getNetworkIpDec(nextHop.getNextHop(), "255.255.255.255");
                            IpAddress nextIpaddress = this.ipAddressServie.querySrcDevice(srcmap);
                            if(nextIpaddress != null){
                                nextHop.setIpAddress(nextIpaddress);

                                // 保存下一跳路由
                                if(ipaddressRoutTable != null){
                                    if(ipaddressRoutTable.getRemoteDevices() != null){
                                        // 校验下一跳的对端设备是否已存在（避免死循环）
                                        List<Map> remoteDevices = JSONArray.parseArray(ipaddressRoutTable.getRemoteDevices(), Map.class);// 对端设备信息集合
                                        for (Map map : remoteDevices){
                                            String remotDevice = map.get("remoteDevice").toString();
                                            String remoteInterface = map.get("remoteInterface").toString();
                                            String remoteUuid = map.get("remoteUuid").toString();
                                            if(nextIpaddress.getDeviceName().equals(remotDevice)
                                                    && nextIpaddress.getInterfaceName().equals(remoteInterface)
                                                    && nextIpaddress.getDeviceUuid().equals(remoteUuid)){
                                                ipAddress.setStatus(2);
                                                ipaddressRoutTable.setStatus(2);
                                                this.routTableService.update(ipaddressRoutTable);
                                                continue outCycle;
                                            }
                                        }
                                    }
                                }
//                                RouteTable ipaddressRoutTable = null;
//                                if(ipaddressRouts.size() > 0){
//                                    ipaddressRoutTable = ipaddressRouts.get(0);
//                                }else{
//                                    ipaddressRoutTable = new RouteTable();
//                                }
                                List<Map> list = null;
                                if(ipaddressRoutTable.getRemoteDevices() != null){
                                    list = JSONArray.parseArray(ipaddressRoutTable.getRemoteDevices(), Map.class);
                                }else{
                                    list = new ArrayList<>();
                                }
                                // 下一跳对端设备信息
                                Map remote = new HashMap();
                                remote.put("remoteDevice", ipAddress.getDeviceName());
                                remote.put("remoteInterface", ipAddress.getInterfaceName());
                                remote.put("remoteUuid", ipAddress.getDeviceUuid());
                                list.add(remote);
                                // 保存所有连接路径
//                            List ipaddressList = JSONArray.parseArray(ipaddressRoutTable.getRemoteDevices(), Map.class);
//                            if(ipaddressList != null){
//                                list.addAll(ipaddressList);
//                            }
                                // 查询下一跳是否已存在
                                params.clear();
                                params.put("ip", nextIpaddress.getIp());
                                params.put("mask", nextIpaddress.getMask());
                                params.put("deviceName", nextIpaddress.getDeviceName());
                                params.put("interfaceName", nextIpaddress.getInterfaceName());
                                params.put("mac", nextIpaddress.getMac());
                                List<RouteTable> nextIpaddressRoutTables = this.routTableService.selectObjByMap(params);
                                RouteTable nextIpaddressRoutTable = null;
                                if(nextIpaddressRoutTables.size() > 0){
                                    nextIpaddressRoutTable = nextIpaddressRoutTables.get(0);
                                }else{
                                    nextIpaddressRoutTable = new RouteTable();
                                }
                                nextIpaddressRoutTable.setRemoteDevices(JSONArray.toJSONString(list));
                                String[] IGNORE_ISOLATOR_PROPERTIES = new String[]{"id"};
                                BeanUtils.copyProperties(nextIpaddress,nextIpaddressRoutTable,IGNORE_ISOLATOR_PROPERTIES);

                                nextIpaddressRoutTable.setRemoteDevice(ipAddress.getDeviceName());
                                nextIpaddressRoutTable.setRemoteInterface(ipAddress.getInterfaceName());
                                nextIpaddressRoutTable.setRemoteUuid(ipAddress.getDeviceUuid());
                                this.routTableService.save(nextIpaddressRoutTable);
                                generatorRout(nextIpaddress, destIp, descMask, time);
                            }
                        }
                    }
                    ipAddress.setRouts(nexthops);
                }else{
                    ipAddress.setStatus(1);
                    ipaddressRoutTable.setStatus(1);
                    this.routTableService.update(ipaddressRoutTable);
                }
                ipAddresses.add(ipAddress);
                return ipAddresses;
            }
        }
        return null;
    }

    public Route queryRout(String descIp, String descMask, String deviceName, Date time){
//        String dm = IpUtil.bitMaskConvertMask(Integer.parseInt(descMask));
//        Map network = IpUtil.getNetworkIp(descIp, dm);
        Map params = new HashMap();
        params.put("deviceName", deviceName);
        params.put("descMask", descMask);
        params.put("orderBy", "mask");
        params.put("orderType", "desc");
        List<Route> routs = null;
        if(time == null){
            routs = this.routService.selectObjByMap(params);
        }else{
            params.put("time", time);
            routs = this.routHistoryService.selectObjByMap(params);
        }
        List<Route> sameRouts = new ArrayList<>();
        if(routs != null){
            for(Route rout : routs){
                if(!StringUtil.isEmpty(rout.getDestination())
                        && !StringUtil.isEmpty(rout.getMask())){
                    boolean flag = isInRange(descIp,
                            IpUtil.decConvertIp(Long.parseLong(rout.getDestination()))
                                    + "/"
                                    +  rout.getMask());
                    if(flag){
                        sameRouts.add(rout);
                    }
                }
            }
        }
        Route rout = null;
        if(sameRouts.size() > 0){
            rout = sameRouts.get(0);
        }
        if(rout == null){
            // dest不存在，查询0.0.0.0
            params.clear();
            params.put("deviceName", deviceName);
            params.put("destination", 0);
            params.put("mask", 0);
            if(time == null){
                rout = this.routService.selectDestDevice(params);
            }else{
                params.put("time", time);
                rout = this.routHistoryService.selectDestDevice(params);
            }
        }
        return rout;
    }

    /**
     * @描述 判断某个ip是否在一个网段内
     * @param ip
     * @param cidr
     * @return
     */
    public static boolean isInRange(String ip, String cidr) {
        String[] ips = ip.split("\\.");
        int ipAddr = (Integer.parseInt(ips[0]) << 24)
                | (Integer.parseInt(ips[1]) << 16)
                | (Integer.parseInt(ips[2]) << 8) | Integer.parseInt(ips[3]);
        int type = Integer.parseInt(cidr.replaceAll(".*/", ""));
        int mask = 0xFFFFFFFF << (32 - type);
        String cidrIp = cidr.replaceAll("/.*", "");
        String[] cidrIps = cidrIp.split("\\.");
        int cidrIpAddr = (Integer.parseInt(cidrIps[0]) << 24)
                | (Integer.parseInt(cidrIps[1]) << 16)
                | (Integer.parseInt(cidrIps[2]) << 8)
                | Integer.parseInt(cidrIps[3]);

        return (ipAddr & mask) == (cidrIpAddr & mask);
    }

    /**
     * 二层设备
     * @param mac
     * @param deviceName
     * @return
     */
    public List<Mac> generetorSrcLayer_2_device(String mac, String deviceName, Date time){
        List list = new ArrayList<>();
        Map params = new HashMap();
        params.clear();
        params.put("mac", mac);
        params.put("deviceName", deviceName);
        List<Mac> srcMacs = this.queryMac(params, time);// 路由起点ip设备mac（包含起点IpMac）
        if(srcMacs.size() > 0){
            Mac srcMac = srcMacs.get(0);
            if(srcMac.getRemoteDevice() == null){
                params.clear();
                params.put("deviceName", deviceName);
                params.put("interfaceName", srcMac.getInterfaceName());
                params.put("tag", "DE");
                List<Mac> macs = this.queryMac(params, time);// 起点设备mac
                if(macs.size() > 0){
                    Mac mac1 = macs.get(0);
                    if(mac1.getRemoteDevice() != null){
                        srcMac.setRemoteDevice(mac1.getRemoteDevice());
                        srcMac.setInterfaceName(mac1.getInterfaceName());
                        srcMac.setRemoteUuid(mac1.getRemoteUuid());
                        list.addAll(generetorSrcLayer_2_device(mac, mac1.getRemoteDevice(),time));
                    }
                }
                list.add(srcMac);
                return list;
            }
        }
        return list;
    }

    public List<Mac> queryMac(Map params, Date time){
        List<Mac> srcMacs = null;
        if(time == null){
            srcMacs = this.macService.selectByMap(params);// 路由起点设备mac（包含起点IpMac）
        }else{
            params.put("time", time);
            srcMacs = this.macHistoryService.selectObjByMap(params);
        }
        return srcMacs;
    }


}
