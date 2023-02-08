package com.metoo.nspm.core.manager.myzabbix.zabbixapi;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.pagehelper.util.StringUtil;
import com.metoo.nspm.core.manager.admin.tools.DateTools;
import com.metoo.nspm.core.manager.admin.tools.SubnetTool;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.core.utils.network.IpV4Util;
import com.metoo.nspm.entity.nspm.*;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@Api("Item管理")
@RequestMapping("/zabbix/item")
@RestController
public class ZabbixItemManagerController {

    @Autowired
    private ZabbixSubnetService zabbixSubnetService;
    @Autowired
    private IMacService macService;
    @Autowired
    private IMacHistoryService macHistoryService;
    @Autowired
    private IArpService arpService;
    @Autowired
    private IArpHistoryService arpHistoryService;
    @Autowired
    private IRoutService routService;
    @Autowired
    private IIPAddressService ipAddressServie;
    @Autowired
    private IRoutTableService routTableService;
    @Autowired
    private IMacVendorService macVendorService;
    @Autowired
    private IAddressService addressService;
    @Autowired
    private IRoutHistoryService routHistoryService;
    @Autowired
    private IIPAddressHistoryService iipAddressHistoryService;
    @Autowired
    private SubnetTool subnetTool;

    public static void main(String[] args) {
        String ip_str = "192.168.10.34 127.0.0.1 3.3.3.3 3.3.3.1 105.70.11.55";
        //将ip_str中每个字符串都添加两个0,使3变成003
        String str = ip_str.replaceAll("(\\d+)","00$1");
        //保留数字后三位
        str = str.replaceAll("0*(\\d{3})","$1"); //如果是"+"则替换的是0没有或多个，后面是连续的数字
        System.out.println(str);
        //字符串切割成字符串数组
        String [] arr = str.split(" +");
        //定义TreeSet集合来进行对象排序
        TreeSet<String> ts = new TreeSet<String>();
        for(int i=0;i<arr.length;i++)
            ts.add(arr[i]);//将字符串数组添加进集合
        for(String ip:ts )
            System.out.println(ip.replaceAll("0*(\\d+)","$1"));
    }

    // 梳理网段
//    @RequestMapping(value = {"/segment1"})
//    public Object segment(){
//        List<Map> ipList = this.topoNodeService.queryMetoo();
//        JSONArray itemsAll = new JSONArray();
//        for (Map map : ipList){
//            JSONArray items = this.zabbixItemService.getItemIpAddress(map.get("ip").toString());
//            if(items != null){
//                itemsAll.addAll(items);
//            }
//        }
//
//        if(itemsAll.size() == 0){
//            return ResponseUtil.ok();
//        }
//        Map<String, List<Object>> map = this.zabbixItemService.ipAddressCombing(itemsAll);
//        for (String key : map.keySet()){
//            int index = key.indexOf("/");
//            String firstIp = key.substring(0, index);
//            int firstMask = Integer.parseInt(key.substring(index + 1));
//            // 插入本地数据库 and 同步ipam
//            // 插如一级ip网段
//            Long firstSubnetId = null;
//            Subnet firstSubnet = this.zabbixSubnetService.selectObjByIp(firstIp, firstMask);
//            if(firstSubnet != null){
//                firstSubnetId = firstSubnet.getId();
//            }
//            if(firstSubnet == null){
//                Subnet subnet = new Subnet();
//                subnet.setIp(IpUtil.ipConvertDec(firstIp));
//                subnet.setMask(firstMask);
//                this.zabbixSubnetService.save(subnet);
//                firstSubnetId = subnet.getId();
//            }
//            // 获取二级网段
//            JSONArray array = JSONArray.parseArray(JSON.toJSONString(map.get(key)));
//            for (Object obj : array) {
//                if(obj instanceof String){
//                    String second = ((String) obj).trim();
//                    int sequence = second.indexOf("/");
//                    String ip = second.substring(0, sequence);
//                    int secondMask = Integer.parseInt(second.substring(sequence + 1));
//                    Subnet secondSubnet = this.zabbixSubnetService.selectObjByIp(ip, secondMask);
//                    if(secondSubnet == null){
//                        Subnet subnet = new Subnet();
//                        subnet.setIp(IpUtil.ipConvertDec(ip));
//                        subnet.setMask(secondMask);
//                        subnet.setParentIp(IpUtil.ipConvertDec(firstIp));
//                        subnet.setParentId(firstSubnetId);
//                        this.zabbixSubnetService.save(subnet);
//                    }
//                }
//                if(obj instanceof JSONObject){
//                    JSONObject object = (JSONObject) obj;
//                    for (String okey : object.keySet()){
//                        String second = ((String) okey).trim();
//                        int sequence = second.indexOf("/");
//                        String secondIp = second.substring(0, sequence);
//                        int secondMask = Integer.parseInt(second.substring(sequence + 1));
//                        Long secondSubnetId = null;
//                        Subnet secondSubnet = this.zabbixSubnetService.selectObjByIp(secondIp, secondMask);
//                        if(secondSubnet != null){
//                            secondSubnetId = secondSubnet.getId();
//                        }
//                        if(secondSubnet == null){
//                            Subnet subnet = new Subnet();
//                            subnet.setIp(IpUtil.ipConvertDec(secondIp));
//                            subnet.setMask(secondMask);
//                            subnet.setParentIp(IpUtil.ipConvertDec(firstIp));
//                            subnet.setParentId(firstSubnetId);
//                            this.zabbixSubnetService.save(subnet);
//                            secondSubnetId = subnet.getId();
//                        }
//                        JSONArray thirdArray = JSONArray.parseArray(object.get(okey).toString());
//                        for (Object thirdKey : thirdArray) {
//                            if(obj instanceof JSONObject){
//                                String third = ((String) thirdKey).trim();
//                                int thirdSequence = third.indexOf("/");
//                                String thirdIp = third.substring(0, thirdSequence);
//                                int thirdMask = Integer.parseInt(third.substring(thirdSequence + 1));
//                                Subnet thirdSubnet = this.zabbixSubnetService.selectObjByIp(thirdIp, thirdMask);
//                                if(thirdSubnet == null){
//                                    Subnet subnet = new Subnet();
//                                    subnet.setIp(IpUtil.ipConvertDec(thirdIp));
//                                    subnet.setMask(thirdMask);
//                                    subnet.setParentIp(IpUtil.ipConvertDec(secondIp));
//                                    subnet.setParentId(secondSubnetId);
//                                    this.zabbixSubnetService.save(subnet);
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
////        this.zabbixItemService.ipAddressCombing(itemsAll);
//
//        // 同步子网ip
//        // 获取所有子网一级
//        List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(null);
//        List<IpDetail> ipdetails = this.ipDetailService.selectObjByMap(null);
//        if(subnets.size() > 0){
//            for(IpDetail ipDetail : ipdetails){
//                if(ipDetail.getIp().equals("0.0.0.0")){
//                    continue;
//                }
//                String ip = IpUtil.decConvertIp(Long.parseLong(ipDetail.getIp()));
//                if(!IpUtil.verifyIp(ip)){
//                    continue;
//                }
//                // 判断ip地址是否属于子网
//                for(Subnet subnet : subnets){
//                    genericNoSubnet(subnet, ipDetail);
//                }
//            }
//        }
//
//        return ResponseUtil.ok();
//    }

//    public Object segment(){
//        List<Map> ipList = this.topoNodeService.queryMetoo();
//        JSONArray itemsAll = new JSONArray();
//        for (Map map : ipList){
//            JSONArray items = this.zabbixItemService.getItemIpAddress(map.get("ip").toString());
//            if(items != null){
//                itemsAll.addAll(items);
//            }
//        }
//        if(itemsAll.size() == 0){
//            return ResponseUtil.ok();
//        }
//        Map<String, List<Object>> map = this.zabbixItemService.ipAddressCombing(itemsAll);
//        // 获取子网标识符
//        Integer sectionId = this.ipamSectionService.getSectionsId();
//        for (String key : map.keySet()){
//            int index = key.indexOf("/");
//            String firstIp = key.substring(0, index);
//            int firstMask = Integer.parseInt(key.substring(index + 1));
//            // 插入本地数据库 and 同步ipam
//            // 插如一级ip网段
//            Long firstSubnetId = null;
//            Subnet firstSubnet = this.zabbixSubnetService.selectObjByIp(firstIp, firstMask);
//            if(firstSubnet != null){
//                firstSubnetId = firstSubnet.getId();
//            }
//            Subnet firstNewSubnet = new Subnet();
//            if(firstSubnet == null){
//                firstNewSubnet.setIp(IpUtil.ipConvertDec(firstIp));
//                firstNewSubnet.setMask(firstMask);
//                this.zabbixSubnetService.save(firstNewSubnet);
//                firstSubnetId = firstNewSubnet.getId();
//            }
//            Integer firstId = this.ipamSubnetService.getSubnetsBySubnet(firstIp, firstMask);
//            if(firstId == null){
//                IpamSubnet subnet = new IpamSubnet();
//                subnet.setSubnet(firstIp);
//                subnet.setMask(firstMask);
//                subnet.setSectionId(sectionId);
//                JSONObject json = this.ipamSubnetService.create(subnet);
//                if(json.getBoolean("success")){
//                    firstId = json.getInteger("id");
//                }
//            }
//            // 获取二级网段
//            JSONArray array = JSONArray.parseArray(JSON.toJSONString(map.get(key)));
//            for (Object o : array) {
//                if(o instanceof String){
//                    String second = ((String) o).trim();
//                    int sequence = second.indexOf("/");
//                    String secondIp = second.substring(0, sequence);
//                    int secondMask = Integer.parseInt(second.substring(sequence + 1));
//                    Subnet secondSubnet = this.zabbixSubnetService.selectObjByIp(secondIp, secondMask);
//                    Subnet secondNewSubnet = new Subnet();
//                    if(secondSubnet == null){
//                        secondNewSubnet.setIp(IpUtil.ipConvertDec(secondIp));
//                        secondNewSubnet.setMask(secondMask);
//                        secondNewSubnet.setParentIp(IpUtil.ipConvertDec(firstIp));
//                        secondNewSubnet.setParentId(firstSubnetId);
//                        this.zabbixSubnetService.save(secondNewSubnet);
//                    }
//                    Integer secondId = this.ipamSubnetService.getSubnetsBySubnet(secondIp, secondMask);
//                    if(secondId == null){
//                        IpamSubnet subnet = new IpamSubnet();
//                        subnet.setSubnet(secondIp);
//                        subnet.setMask(secondMask);
//                        subnet.setSectionId(sectionId);
//                        subnet.setMasterSubnetId(firstId);
//                        JSONObject json = this.ipamSubnetService.create(subnet);
//                        if(json.getBoolean("success")){
//                            secondId = json.getInteger("id");
//                        }
//                    }
//                }
//                if(o instanceof JSONObject){
//                    JSONObject object = (JSONObject) o;
//                    for (String okey : object.keySet()){
//                        String second = ((String) okey).trim();
//                        int sequence = second.indexOf("/");
//                        String secondIp = second.substring(0, sequence);
//                        int secondMask = Integer.parseInt(second.substring(sequence + 1));
//                        Long secondSubnetId = null;
//                        Subnet secondSubnet = this.zabbixSubnetService.selectObjByIp(secondIp, secondMask);
//                        if(secondSubnet != null){
//                            secondSubnetId = secondSubnet.getId();
//                        }
//                        Subnet secondNewSubnet = new Subnet();
//                        if(secondSubnet == null){
//                            secondNewSubnet.setIp(IpUtil.ipConvertDec(secondIp));
//                            secondNewSubnet.setMask(secondMask);
//                            secondNewSubnet.setParentIp(IpUtil.ipConvertDec(firstIp));
//                            secondNewSubnet.setParentId(firstSubnetId);
//                            this.zabbixSubnetService.save(secondNewSubnet);
//                            secondSubnetId = secondNewSubnet.getId();
//                        }
//                        Integer secondId = this.ipamSubnetService.getSubnetsBySubnet(secondIp, secondMask);
//                        if(secondId == null){
//                            IpamSubnet subnet = new IpamSubnet();
//                            subnet.setSubnet(secondIp);
//                            subnet.setMask(secondMask);
//                            subnet.setSectionId(sectionId);
//                            subnet.setMasterSubnetId(firstId);
//                            JSONObject json = this.ipamSubnetService.create(subnet);
//                            if(json.getBoolean("success")){
//                                secondId = json.getInteger("id");
//                            }
//                        }
//                        JSONArray thirdArray = JSONArray.parseArray(object.get(okey).toString());
//                        for (Object thirdKey : thirdArray) {
//                            if(o instanceof JSONObject){
//                                String third = ((String) thirdKey).trim();
//                                int thirdSequence = third.indexOf("/");
//                                String thirdIp = third.substring(0, thirdSequence);
//                                int thirdMask = Integer.parseInt(third.substring(thirdSequence + 1));
//                                Subnet thirdSubnet = this.zabbixSubnetService.selectObjByIp(thirdIp, thirdMask);
//                                if(thirdSubnet == null){
//                                    Subnet subnet = new Subnet();
//                                    subnet.setIp(IpUtil.ipConvertDec(thirdIp));
//                                    subnet.setMask(thirdMask);
//                                    subnet.setParentIp(IpUtil.ipConvertDec(secondIp));
//                                    subnet.setParentId(secondSubnetId);
//                                    this.zabbixSubnetService.save(subnet);
//                                }
//                                Integer thirdId = this.ipamSubnetService.getSubnetsBySubnet(thirdIp, thirdMask);
//                                if(thirdId == null){
//                                    IpamSubnet subnet = new IpamSubnet();
//                                    subnet.setSubnet(thirdIp);
//                                    subnet.setMask(thirdMask);
//                                    subnet.setSectionId(sectionId);
//                                    subnet.setMasterSubnetId(secondId);
//                                    this.ipamSubnetService.create(subnet);
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
//        this.zabbixItemService.ipAddressCombing(itemsAll);
//        // 同步子网ip
//        // 获取所有子网一级
//        List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(null);
//        List<IpDetail> ipdetails = this.ipDetailService.selectObjByMap(null);
//        if(subnets.size() > 0){
//            for(IpDetail ipDetail : ipdetails){
//                if(ipDetail.getIp().equals("0.0.0.0")){
//                    continue;
//                }
//                String ip = IpUtil.decConvertIp(Long.parseLong(ipDetail.getIp()));
//                if(!IpUtil.verifyIp(ip)){
//                    continue;
//                }
//                // 判断ip地址是否属于子网
//                for(Subnet subnet : subnets){
//                    genericNoSubnet(subnet, ipDetail);
//                }
//            }
//        }
//
//        return ResponseUtil.ok();
//    }

    public void genericNoSubnet(Subnet subnet, IpDetail ipDetail){
        List<Subnet> childs = this.zabbixSubnetService.selectSubnetByParentId(subnet.getId());
        if(childs.size() > 0){
            for(Subnet child : childs){
                genericNoSubnet(child, ipDetail);
            }
        }else{
            // 判断ip是否属于从属子网
            boolean flag = IpUtil.ipIsInNet(IpUtil.decConvertIp(Long.parseLong(ipDetail.getIp())), subnet.getIp() + "/" + subnet.getMask());
            if(flag){
                Address obj = this.addressService.selectObjByIp(ipDetail.getIp());
                if(obj != null){
                    obj.setSubnetId(subnet.getId());
                    int i = this.addressService.update(obj);
                }else{
                    Address address = new Address();
                    address.setIp(ipDetail.getIp());
                    address.setHostName(ipDetail.getDeviceName());
                    address.setMac(ipDetail.getMac());
                    address.setSubnetId(subnet.getId());
                    int i = this.addressService.save(address);
                }
            }
        }
    }

    @RequestMapping("/parseJson")
    public Object parseJson(@RequestBody String json){
        JSONObject aaaaa = JSONObject.parseObject(json);
        for (String ss : aaaaa.keySet()){
            JSONObject bbbb = JSONObject.parseObject(aaaaa.get(ss).toString());
            for (String key : bbbb.keySet()){
                JSONArray array = JSONArray.parseArray(bbbb.get(key).toString());
                for (Object o : array) {
                    if(o instanceof String){
                        System.out.println("String：" + o);
                    }
                    if(o instanceof JSONObject){
                        JSONObject object = (JSONObject) o;
                        System.out.println("Map" + object);
                    }
                }
            }
        }
        return null;
    }

//    @ApiOperation("查询mac")
//    @GetMapping(value = {"/obj/mac","/obj/mac/{uuid}","/obj/mac/{time}","/obj/mac/{uuid}/{time}"})
//    public Object getObjMac(@PathVariable(value = "uuid", required = false) String uuid,
//                             @PathVariable(value="time", required = false)
//                             @DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss") Date time){
//        Map params = new HashMap();
//        List<Mac> macs = null;
//        if(time == null){
//            if(uuid != null && !uuid.equals("")){
//                params.put("uuid", uuid);
//                params.put("tag", "DT");
//                macs = this.macService.selectByMap(params);
//            }else{
//                params.clear();
//                params.put("tag", "DE");
//                macs = this.macService.selectByMap(params);
//            }
//        }else{
//            params.put("time", DateTools.getCurrentTimeNoSecond(time));
//            if(uuid != null && !uuid.equals("")){
//                params.put("uuid", uuid);
//                params.put("tag", "DT");
//                macs = this.macHistoryService.selectObjByMap(params);
//            }else{
//                params.put("tag", "DE");
//                macs = this.macHistoryService.selectObjByMap(params);
//            }
//        }
//
//        if(macs != null && macs.size() > 0){
//            ExecutorService exe = Executors.newFixedThreadPool(macs.size());
//            for(Mac mac : macs){
//                if(mac.getDeviceIp() != null && mac.getInterfaceName() != null){
//                    exe.execute(new Thread(new Runnable() {
//                        @Override
//                        public void run() {
//                            String interfaceName = itemUtil.getInterfaceName(
//                                    mac.getDeviceIp(),
//                                    mac.getInterfaceName());
//                            mac.setInterfaceName(interfaceName);
//                        }
//                    }));
//                }
//            }
//            exe.shutdown();
//            while (true) {
//                if (exe.isTerminated()){
//                    for(Mac mac : macs){
//                        if(mac.getMac() != null && !mac.getMac().equals("")){
//                            String macAddr = mac.getMac();
//                            int one_index = macAddr.indexOf(":");
//                            String one = macAddr.substring(0, one_index);
//                            if(one.equals("0")){
//                                one = "00";
//                            }
//                            int tow_index = macAddr.indexOf(":", one_index + 1);
//                            String two = macAddr.substring(one_index, tow_index);
//                            if(two.equals("0")){
//                                two = "00";
//                            }
//                            int three_index = macAddr.indexOf(":", tow_index + 1);
//                            String three = macAddr.substring(tow_index, three_index);
//                            if(three.equals("0")){
//                                three = "00";
//                            }
////                            macAddr = macAddr.substring(0, index);
//                            macAddr = one + two + three;
//                            params.clear();
//                            params.put("mac", macAddr);
//                            List<MacVendor> macVendors = this.macVendorService.selectObjByMap(params);
//                            if(macVendors.size() > 0){
//                                MacVendor macVendor = macVendors.get(0);
//                                mac.setVendor(macVendor.getVendor());
//                            }
//
//                        }
//                    }
//                    return ResponseUtil.ok(macs);
//                }
//            }
//        }
//        return ResponseUtil.ok();
//    }

    @ApiOperation("查询mac")
    @GetMapping(value = {"/obj/mac"})
    public Object getObjMac(@RequestParam(value = "uuid", required = false) String uuid,
                            @RequestParam(value="time", required = false)
                            @DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss") Date time){
        Map params = new HashMap();
        List<Mac> macs = null;
        if(time == null){
            if(uuid != null && !uuid.equals("")){
                params.put("uuid", uuid);
                params.put("tag", "DT");
                macs = this.macService.selectByMap(params);
            }else{
                params.clear();
                params.put("tag", "DE");
                macs = this.macService.selectByMap(params);
            }
        }else{
            params.put("time", DateTools.getCurrentTimeNoSecond(time));
            if(uuid != null && !uuid.equals("")){
                params.put("uuid", uuid);
                params.put("tag", "DT");
                macs = this.macHistoryService.selectObjByMap(params);
            }else{
                params.put("tag", "DE");
                macs = this.macHistoryService.selectObjByMap(params);
            }
        }
        if(macs != null && macs.size() > 0){
//            ExecutorService exe = Executors.newFixedThreadPool(macs.size());
//            for(Mac mac : macs){
//                if(mac.getDeviceIp() != null && mac.getInterfaceName() != null){
//                    exe.execute(new Thread(new Runnable() {
//                        @Override
//                        public void run() {
//                            String interfaceName = itemUtil.getInterfaceName(
//                                    mac.getDeviceIp(),
//                                    mac.getInterfaceName());
//                            mac.setInterfaceName(interfaceName);
//                        }
//                    }));
//                }
//            }
//            exe.shutdown();
//            while (true) {
//                if (exe.isTerminated()){
                    for(Mac mac : macs){
                        if(mac.getMac() != null && !mac.getMac().equals("")){
                            String macAddr = mac.getMac();
                            int one_index = macAddr.indexOf(":");
                            String one = macAddr.substring(0, one_index);
                            if(one.equals("0")){
                                one = "00";
                            }
                            int tow_index = macAddr.indexOf(":", one_index + 1);
                            String two = macAddr.substring(one_index, tow_index);
                            if(two.equals("0")){
                                two = "00";
                            }
                            int three_index = macAddr.indexOf(":", tow_index + 1);
                            String three = macAddr.substring(tow_index, three_index);
                            if(three.equals("0")){
                                three = "00";
                            }
//                            macAddr = macAddr.substring(0, index);
                            macAddr = one + two + three;
                            params.clear();
                            params.put("mac", macAddr);
                            List<MacVendor> macVendors = this.macVendorService.selectObjByMap(params);
                            if(macVendors.size() > 0){
                                MacVendor macVendor = macVendors.get(0);
                                mac.setVendor(macVendor.getVendor());
                            }

                        }
                    }
                    return ResponseUtil.ok(macs);
                }
//            }
//        }
        return ResponseUtil.ok();
    }

    @GetMapping("/batch/delete/arp")
    public void batchArp(@DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")Date time){
        Map params = new HashMap();
        params.put("beforeTime", time);
        try {
            List<Arp> arps = this.arpHistoryService.selectObjByMap(params);
            if(arps.size() > 0){
                this.arpHistoryService.batchDelete(arps);
            }
            try {
                List<Mac> macs = this.macHistoryService.selectObjByMap(params);
                if(macs.size() > 0){
                    this.macHistoryService.batchDelete(macs);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            try {
                List<Route> routList = this.routHistoryService.selectObjByMap(params);
                if(routList.size() > 0){
                    this.routHistoryService.batchDelete(routList);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            try {
                List<IpAddress> ipAddresses = this.iipAddressHistoryService.selectObjByMap(params);
                if(ipAddresses.size() > 0){
                    this.iipAddressHistoryService.batchDelete(ipAddresses);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

//    @ApiOperation("arp")
//    @GetMapping(value = {"/obj/arp","/obj/arp/{uuid}","/obj/arp/{time}","/obj/arp/{uuid}/{time}"})
//    public Object arp(@PathVariable(value = "uuid", required = false) String uuid,
//                      @PathVariable(value="time", required = false)
//                      @DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss") Date time){
//        Map params = new HashMap();
//        List<Arp> arps = null;
//        if(time == null){
//            if(uuid != null){
//                params.clear();
//                params.put("uuid", uuid);
//            }
//            arps = this.arpService.selectDistinctObjByMap(params);
//        }else{
//            params.clear();
//            params.put("time", DateTools.getCurrentTimeNoSecond(time));
//            if(uuid != null){
//                params.put("uuid", uuid);
//            }
//            arps = this.arpHistoryService.selectDistinctObjByMap(params);
//        }
//        if(arps.size() > 0){
//            ExecutorService exe = Executors.newFixedThreadPool(arps.size());
//            for(Arp arp : arps){
//                if(arp.getDeviceIp() != null && arp.getInterfaceName() != null){
//                    exe.execute(new Thread(new Runnable() {
//                        @Override
//                        public void run() {
//                            String interfaceName = itemUtil.getInterfaceName(
//                                    arp.getDeviceIp(),
//                                    arp.getInterfaceName());
//                            arp.setInterfaceName(interfaceName);
//                        }
//                    }));
//                }
//            }
//            if(exe != null){
//                exe.shutdown();
//            }
//            while (true) {
//                if (exe.isTerminated()) {
//                    // 排序
//                    SortedSet set = IpV4Util.sort(arps);
//                    return ResponseUtil.ok(set);
//
//                }
//            }
//        }
//        return ResponseUtil.ok();
//    }

    @ApiOperation("arp")
    @GetMapping(value = {"/obj/arp"})
    public Object arp(@RequestParam(value = "uuid", required = false) String uuid,
                      @RequestParam(value="time", required = false)
                      @DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss") Date time){
        Map params = new HashMap();
        List<Arp> arps = null;
        if(time == null){
            if(!StringUtils.isEmpty(uuid)){
                params.clear();
                params.put("uuid", uuid);
            }
            arps = this.arpService.selectDistinctObjByMap(params);
        }else{
            params.clear();
            params.put("time", DateTools.getCurrentTimeNoSecond(time));
            if(uuid != null){
                params.put("uuid", uuid);
            }
            arps = this.arpHistoryService.selectDistinctObjByMap(params);
        }
        SortedSet set = IpV4Util.sort(arps);
        return ResponseUtil.ok(set);
//        if(arps.size() > 0){
//            ExecutorService exe = Executors.newFixedThreadPool(arps.size());
//            for(Arp arp : arps){
//                if(arp.getDeviceIp() != null && arp.getInterfaceName() != null){
//                    exe.execute(new Thread(new Runnable() {
//                        @Override
//                        public void run() {
//                            String interfaceName = itemUtil.getInterfaceName(
//                                    arp.getDeviceIp(),
//                                    arp.getInterfaceName());
//                            arp.setInterfaceName(interfaceName);
//                        }
//                    }));
//                }
//            }
//            if(exe != null){
//                exe.shutdown();
//            }
//            while (true) {
//                if (exe.isTerminated()) {
//                    // 排序
//                    SortedSet set = IpV4Util.sort(arps);
//                    return ResponseUtil.ok(set);
//
//                }
//            }
//        }
    }

    @ApiOperation("arp:E")
    @GetMapping(value = "/obj/arp/tag")
    public Object arpTag(){
        Map params = new HashMap();
        params.put("tag", "E");
        List<Arp> arps = this.arpService.selectObjByMap(params);
        for (int i = 0; i < arps.size(); i++) {
            for (int j = 0; j < arps.size(); j++) {
                Arp arp = arps.get(i);
                Arp arpRM = arps.get(j);
                if(arp.getDeviceName().equals(arpRM.getRemoteDevice())
                        && arp.getInterfaceName().equals(arpRM.getRemoteInterface())){
                    arps.remove(arps.get(j));
                }
            }
        }
//        List<Arp> arps = this.arpService.selectEAndRemote(params);
//        if(arps.size() > 0){
//            ExecutorService exe = Executors.newFixedThreadPool(arps.size());
//            for(Arp arp : arps){
//                if(arp.getDeviceIp() != null && arp.getInterfaceName() != null){
//                    exe.execute(new Thread(new Runnable() {
//                        @Override
//                        public void run() {
//                            String interfaceName = itemUtil.getInterfaceName(
//                                    arp.getDeviceIp(),
//                                    arp.getInterfaceName());
//                            arp.setInterfaceName(interfaceName);
//                        }
//                    }));
//                }
//            }
//        }
        return ResponseUtil.ok(arps);
    }

    @ApiOperation("arp:E")
    @GetMapping(value = "/obj/arp/e")
    public Object arpTagE() {
        Map params = new HashMap();
        params.put("tag", "E");
        List<Arp> arps = this.arpService.selectObjByMap(params);
        for (int i = 0; i < arps.size(); i++) {
            for (int j = 0; j < arps.size(); j++) {
                Arp arp = arps.get(i);
                Arp arpRM = arps.get(j);
                if(arp.getDeviceName().equals(arpRM.getRemoteDevice())
                    && arp.getInterfaceName().equals(arpRM.getRemoteInterface())){
                    arps.remove(arps.get(j));
                }
            }
        }
        return arps;
    }

    @ApiOperation("查询rout")
    @GetMapping(value = "/obj/rout")
    public Object rout(String srcIp, String destIp){
        if(IpUtil.verifyIp(srcIp)){
            return ResponseUtil.badArgument("源地址不符合规范");
        }
        if(IpUtil.verifyIp(srcIp)){
            return ResponseUtil.badArgument("目的地址不符合规范");
        }
        Map params = new HashMap();
        // 根据源Ip查询ipaddress
        params.put("ip", srcIp);
        this.ipAddressServie.selectObjByMap(params);
        return ResponseUtil.ok();
    }

    /**
     * 路由查询
     * 根据起点设备查询ipaddress
     */
    @RequestMapping("/query")
    public Object queryRout(String ip, Integer mask){
        if(mask == null){
            mask = 32;
        }
        String mask2 = IpUtil.bitMaskConvertMask(mask);
        Map params = IpUtil.getNetworkIp(ip, mask2);
        // 起点设备
        IpAddress ipaddress = this.ipAddressServie.querySrcDevice(params);
        return ResponseUtil.ok(ipaddress);
    }

    @RequestMapping("/query/dest")
    public Object queryRoutDest(String ip, Integer mask){
        if(mask == null){
            mask = 32;
        }
        String mask2 = IpUtil.bitMaskConvertMask(mask);
        Map params = IpUtil.getNetworkIpDec(ip, mask2);
        // 获取nexthop设备
        List<Route> nexthops = this.routService.queryDestDevice(params);
        for (Route rout : nexthops){
            // 根据下一跳查询ipaddress(设备)
            params = IpUtil.getNetworkIp(rout.getNextHop(), "255.255.255.255");
            // 起点设备
            IpAddress ipaddress = this.ipAddressServie.querySrcDevice(params);
        }
        return ResponseUtil.ok(nexthops);
    }

    /**
     * 查询路由表
     * @param srcIp 起点Ip
     * @param destIp 终点Ip
     * @return
     */
    @RequestMapping("/routTable")
    public Object routTable(String srcIp, String destIp){
        if(StringUtil.isEmpty(srcIp)){
            return ResponseUtil.badArgument("起点Ip不能为空");
        }
        if(!IpUtil.verifyIp(srcIp)){
            return ResponseUtil.badArgument("起点Ip格式错误");
        }
        if(StringUtil.isEmpty(destIp)){
            return ResponseUtil.badArgument("终点Ip不能为空");
        }
        if(!IpUtil.verifyIp(destIp)){
            return ResponseUtil.badArgument("终点Ip格式错误");
        }
        Map origin = this.subnetTool.verifyIpBelongSubnet(srcIp);
        if(origin == null || origin.isEmpty()){
            return ResponseUtil.badArgument("起点Ip不存在");
        }
        IpAddress srcIpAddress = this.ipAddressServie.querySrcDevice(origin);
        if(srcIpAddress == null){
            return ResponseUtil.badArgument("起点Ip不存在");
        }
        // 获取起点ip网络地址和广播地址
        Map dest = this.subnetTool.verifyIpBelongSubnet(destIp);
        if(dest == null || dest.isEmpty()){
            return ResponseUtil.badArgument("终点Ip不存在");
        }
        // 终点设备
        IpAddress destIpAddress = this.ipAddressServie.querySrcDevice(dest);
        if(destIpAddress == null){
            return ResponseUtil.badArgument("终点Ip不存在");
        }
        Map map = new HashMap();
        map.put("destinationDevice", destIpAddress);
        this.routTableService.truncateTable();
        Map params = new HashMap();
        // 保存起点设备
        params.clear();
        params.put("ip", srcIpAddress.getIp());
        params.put("mask", srcIpAddress.getMask());
        params.put("deviceName", srcIpAddress.getDeviceName());
        params.put("interfaceName", srcIpAddress.getInterfaceName());
        params.put("mac", srcIpAddress.getMac());
        List<RouteTable> routTables = this.routTableService.selectObjByMap(params);
        RouteTable srcRoutTable = null;
        if(routTables.size() > 0){
            srcRoutTable = routTables.get(0);
        }else{
            srcRoutTable = new RouteTable();
        }
        String[] IGNORE_ISOLATOR_PROPERTIES = new String[]{"id"};
        BeanUtils.copyProperties(srcIpAddress, srcRoutTable, IGNORE_ISOLATOR_PROPERTIES);
        this.routTableService.save(srcRoutTable);
        /*List<IpAddress> ipAddresses = */
        List<RouteTable> routers = new ArrayList<>();
        Map<String, RouteTable> routersMap = new HashMap();
        this.generatorRout1(srcIpAddress, destIp, destIpAddress.getMask(), routersMap);
        if(!routersMap.isEmpty()){
            List<RouteTable> a = routersMap.entrySet().stream().map(m -> m.getValue()).collect(Collectors.toList());
            routers.addAll(a);
        }
        routers.add(srcRoutTable);

        List<RouteTable> routTableList = this.routTableService.selectObjByMap(null);
        map.put("destinationDevice", destIpAddress);
        map.put("routTable", routers);
        return ResponseUtil.ok(map);
    }

    /**
     * 验证Ip是否属于子网
     * @param subnet
     * @param ip
     * @return
     */
    public Subnet verifySubnetByIp(Subnet subnet, String ip){
        List<Subnet> childs = this.zabbixSubnetService.selectSubnetByParentId(subnet.getId());
        if(childs.size() > 0){
            for(Subnet child : childs){
                Subnet csubnet = verifySubnetByIp(child, ip);
                if(csubnet != null){
                    return csubnet;
                }
            }
        }else{
            // 判断ip是否属于从属子网
            boolean flag = IpUtil.ipIsInNet(ip, subnet.getIp() + "/" + subnet.getMask());
            if(flag){
                return subnet;
            }
        }
        return null;
    }

    // 存在死循环问题

    /**
     *
     * @param ipAddress 起点设备
     * @param destIp 终点ip
     * @param descMask 终点Mask
     * @return
     */
    public List<RouteTable> generatorRout1(IpAddress ipAddress, String destIp, String descMask, Map<String, RouteTable> routeMap) {
        List<IpAddress> ipAddresses = new ArrayList<>();
        if (ipAddress != null) {
            ipAddress.setStatus(0);
            Map params = new HashMap();
            // 查询当前设备在路由表中是否已记录
            RouteTable ipaddressRoutTable = new RouteTable();
            RouteTable r = routeMap.get(ipAddress.getIp());
            if(r != null){
                if(r.getMask().equals(ipAddress.getMask()) &&
                        r.getRemoteDevice().equals(ipAddress.getDeviceName()) &&
                        r.getRemoteInterface().equals(ipAddress.getInterfaceName()) &&
                        r.getMac().equals(ipAddress.getMac())){
                    ipaddressRoutTable = r;
                }
            }
            Route rout = this.querySrcRout(destIp, descMask, ipAddress.getDeviceName());// 查询起点路由
            if(rout != null){
                params.clear();
                params.put("deviceName", ipAddress.getDeviceName());
                params.put("destination", rout.getDestination());
                params.put("mask", rout.getMask());
                List<Route> nexthops = this.routService.selectNextHopDevice(params);
                if (nexthops.size() > 0) {
                    outCycle:for (Route nextHop : nexthops) {
                        if(nextHop.getNextHop() != null && !nextHop.getNextHop().equals("")){
                            String nexeIp = nextHop.getNextHop();
                            // 这里使用continue，继续进行下一个nexthop
                            if(nexeIp == null || nexeIp.equals("") || nexeIp.equals("127.0.0.1") || nexeIp.equals("0.0.0.0")){
                                // 不在执行下一跳，为终端设备
                                RouteTable routTable = routeMap.get(ipAddress.getIp());
                                routTable.setStatus(3);
                                routeMap.put(ipAddress.getIp(), routTable);
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

                                                RouteTable routTable = routeMap.get(ipAddress.getIp());
                                                routTable.setStatus(2);
                                                routeMap.put(ipAddress.getIp(), routTable);
                                                continue outCycle;
                                            }
                                        }
                                    }
                                }
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
                                // 查询下一跳是否已存在
                                RouteTable nextIpaddressRoutTable = new RouteTable();

                                RouteTable r2 = routeMap.get(nextIpaddress.getIp());
                                if(r2 != null){
                                    if(r2.getMask().equals(nextIpaddress.getMask()) &&
                                            r2.getRemoteDevice().equals(nextIpaddress.getDeviceName()) &&
                                            r2.getRemoteInterface().equals(nextIpaddress.getInterfaceName()) &&
                                            r2.getMac().equals(nextIpaddress.getMac())){
                                        nextIpaddressRoutTable = r2;
                                    }
                                }
                                nextIpaddressRoutTable.setRemoteDevices(JSONArray.toJSONString(list));
                                String[] IGNORE_ISOLATOR_PROPERTIES = new String[]{"id"};
                                BeanUtils.copyProperties(nextIpaddress,nextIpaddressRoutTable,IGNORE_ISOLATOR_PROPERTIES);
                                nextIpaddressRoutTable.setRemoteDevice(ipAddress.getDeviceName());
                                nextIpaddressRoutTable.setRemoteInterface(ipAddress.getInterfaceName());
                                nextIpaddressRoutTable.setRemoteUuid(ipAddress.getDeviceUuid());
                                routeMap.put(nextIpaddressRoutTable.getIp(), nextIpaddressRoutTable);
                                generatorRout1(nextIpaddress, destIp, descMask, routeMap);
                            }
                        }
                    }
                    ipAddress.setRouts(nexthops);
                }else{
                    // 修改集合数据，
                    RouteTable routTable = routeMap.get(ipAddress.getIp());
                    routTable.setStatus(1);
                    routeMap.put(ipAddress.getIp(), routTable);
                }
                ipAddresses.add(ipAddress);
                return null;
            }
        }
        return null;
    }

    public List<IpAddress> generatorRout(IpAddress ipAddress, String destIp, String descMask) {
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
            RouteTable ipaddressRoutTable = new RouteTable();
            if(ipaddressRouts.size() > 0) {
                ipaddressRoutTable = ipaddressRouts.get(0);

            }
            Route rout = this.querySrcRout(destIp, descMask, ipAddress.getDeviceName());// 查询起点路由
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
                                generatorRout(nextIpaddress, destIp, descMask);
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

    // 获取起点路由

    /**
     *
     * @param descIp 终点IP
     * @param descMask 终点Mask
     * @param deviceName
     * @return
     */
    @RequestMapping("/querySrcRout")
    public Route querySrcRout(String descIp, String descMask, String deviceName){
//        String dm = IpUtil.bitMaskConvertMask(Integer.parseInt(descMask));
//        Map network = IpUtil.getNetworkIp(descIp, dm);
        Map params = new HashMap();
        params.put("deviceName", deviceName);
        params.put("descMask", descMask);
        params.put("orderBy", "mask");
        params.put("orderType", "desc");
        List<Route> routs = this.routService.selectObjByMap(params);
        List<Route> sameRouts = new ArrayList<>();
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
            rout = this.routService.selectDestDevice(params);
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

}

