package com.metoo.nspm.core.manager.admin.action;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.service.topo.ITopoNodeService;
import com.metoo.nspm.core.service.api.zabbix.ZabbixItemService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.entity.nspm.*;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Api("子网管理")
@RequestMapping("/admin/subnet")
@RestController
public class SubnetManagerController {

    @Autowired
    private ZabbixSubnetService zabbixSubnetService;
    @Autowired
    private IAddressService addressService;
    @Autowired
    private IpDetailService ipDetailService;
    @Autowired
    private ITopoNodeService topoNodeService;
    @Autowired
    private ZabbixItemService zabbixItemService;
    @Autowired
    private IVlanService vlanService;
    @Autowired
    private IDomainService domainService;
    @Autowired
    private IIPAddressService ipAddressService;

    public static void main(String[] args) {
        List list = new ArrayList();
        List list1 = new ArrayList();
        list1.add(4);
        List list2 = new ArrayList();
        list2.add(4);
        List list3 = new ArrayList();
        list3.add(4);
        list.addAll(list1);
        list.addAll(list2);
        list.addAll(list3);
//        int suma =  list.stream().map(e -> e.getAge()).reduce(Integer::sum).get();//求和  87
//        long sum = list.stream().reduce(Integer::sum).orElse(0);
        IntSummaryStatistics summaryStatistics = list.stream().mapToInt((s) -> (int) s).summaryStatistics();
        System.out.println(summaryStatistics.getCount());
        System.out.println(summaryStatistics.getMax());
        System.out.println(summaryStatistics.getSum());

        String ip = "155.0.0.0";
        String mask = "255.0.0.0";
        Map map = IpUtil.getNetworkIpDec(ip, mask);
        System.out.println(map);
    }


//    @RequestMapping(value = {"/comb"})
//    public Object comb(){
//        List<Map> ipList = this.topoNodeService.queryNetworkElement();
//        if(ipList.size() > 0){
//            ExecutorService exe = Executors.newFixedThreadPool(ipList.size());
//            JSONArray itemsAll = new JSONArray();
//            for (Map map : ipList){
//                exe.execute(new Thread(new Runnable() {
//                    @Override
//                    public void run() {
//                        JSONArray items = zabbixItemService.getItemIpAddress(map.get("ip").toString());
//                        if(items != null){
//                            itemsAll.addAll(items);
//                        }
//                    }
//                }));
//            }
//            if(exe != null){
//                exe.shutdown();
//            }
//            while (true) {
//                if (exe == null || exe.isTerminated()) {
//                    if(itemsAll.size() == 0){
//                        return ResponseUtil.ok();
//                    }
//                    Map<String, List<Object>> map = this.zabbixItemService.ipAddressCombing(itemsAll);
//                    for (String key : map.keySet()){
//                        int index = key.indexOf("/");
//                        String firstIp = key.substring(0, index);
//                        int firstMask = Integer.parseInt(key.substring(index + 1));
//                        // 插入本地数据库 and 同步ipam
//                        // 插如一级ip网段
//                        Long firstSubnetId = null;
//                        Subnet firstSubnet = this.zabbixSubnetService.selectObjByIp(firstIp, firstMask);
//                        if(firstSubnet != null){
//                            firstSubnetId = firstSubnet.getId();
//                        }
//                        if(firstSubnet == null){
//                            Subnet subnet = new Subnet();
//                            subnet.setIp(IpUtil.ipConvertDec(firstIp));
//                            subnet.setMask(firstMask);
//                            this.zabbixSubnetService.save(subnet);
//                            firstSubnetId = subnet.getId();
//                        }
//                        // 获取二级网段
//                        JSONArray array = JSONArray.parseArray(JSON.toJSONString(map.get(key)));
//                        for (Object obj : array) {
//                            if(obj instanceof String){
//                                String second = ((String) obj).trim();
//                                int sequence = second.indexOf("/");
//                                String ip = second.substring(0, sequence);
//                                int secondMask = Integer.parseInt(second.substring(sequence + 1));
//                                Subnet secondSubnet = this.zabbixSubnetService.selectObjByIp(ip, secondMask);
//                                if(secondSubnet == null){
//                                    Subnet subnet = new Subnet();
//                                    subnet.setIp(IpUtil.ipConvertDec(ip));
//                                    subnet.setMask(secondMask);
//                                    subnet.setParentIp(IpUtil.ipConvertDec(firstIp));
//                                    subnet.setParentId(firstSubnetId);
//                                    this.zabbixSubnetService.save(subnet);
//                                }
//                            }
//                            if(obj instanceof JSONObject){
//                                JSONObject object = (JSONObject) obj;
//                                for (String okey : object.keySet()){
//                                    String second = ((String) okey).trim();
//                                    int sequence = second.indexOf("/");
//                                    String secondIp = second.substring(0, sequence);
//                                    int secondMask = Integer.parseInt(second.substring(sequence + 1));
//                                    Long secondSubnetId = null;
//                                    Subnet secondSubnet = this.zabbixSubnetService.selectObjByIp(secondIp, secondMask);
//                                    if(secondSubnet != null){
//                                        secondSubnetId = secondSubnet.getId();
//                                    }
//                                    if(secondSubnet == null){
//                                        Subnet subnet = new Subnet();
//                                        subnet.setIp(IpUtil.ipConvertDec(secondIp));
//                                        subnet.setMask(secondMask);
//                                        subnet.setParentIp(IpUtil.ipConvertDec(firstIp));
//                                        subnet.setParentId(firstSubnetId);
//                                        this.zabbixSubnetService.save(subnet);
//                                        secondSubnetId = subnet.getId();
//                                    }
//                                    JSONArray thirdArray = JSONArray.parseArray(object.get(okey).toString());
//                                    for (Object thirdKey : thirdArray) {
//                                        if(obj instanceof JSONObject){
//                                            String third = ((String) thirdKey).trim();
//                                            int thirdSequence = third.indexOf("/");
//                                            String thirdIp = third.substring(0, thirdSequence);
//                                            int thirdMask = Integer.parseInt(third.substring(thirdSequence + 1));
//                                            Subnet thirdSubnet = this.zabbixSubnetService.selectObjByIp(thirdIp, thirdMask);
//                                            if(thirdSubnet == null){
//                                                Subnet subnet = new Subnet();
//                                                subnet.setIp(IpUtil.ipConvertDec(thirdIp));
//                                                subnet.setMask(thirdMask);
//                                                subnet.setParentIp(IpUtil.ipConvertDec(secondIp));
//                                                subnet.setParentId(secondSubnetId);
//                                                this.zabbixSubnetService.save(subnet);
//                                            }
//                                        }
//                                    }
//                                }
//                            }
//                        }
//                    }
//                    // 同步子网ip
//                    // 获取所有子网一级
//                    List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(null);
//                    List<IpDetail> ipdetails = this.ipDetailService.selectObjByMap(null);
//                    if(subnets.size() > 0){
//                        for(IpDetail ipDetail : ipdetails){
//                            if(ipDetail.getIp() != null){
//                                if(ipDetail.getIp().equals("0.0.0.0")){
//                                    continue;
//                                }
//                                String ip = IpUtil.decConvertIp(Long.parseLong(ipDetail.getIp()));
//                                if(!IpUtil.verifyIp(ip)){
//                                    continue;
//                                }
//                                // 判断ip地址是否属于子网
//                                for(Subnet subnet : subnets){
//                                    genericNoSubnet(subnet, ipDetail);
//                                }
//                            }
//                        }
//                    }
//                    return null;
//                }
//            }
//        }
//        return null;
//    }

    @RequestMapping(value = {"/comb"})
    public Object comb(){
        Map params = new HashMap();
        params.put("NotIp", IpUtil.ipConvertDec("127.0.0.1"));
        List<IpAddress> ipAddresses = this.ipAddressService.selectObjByMap(params);
        Map<String, List<Object>> map = this.zabbixItemService.ipAddressCombingByDB(ipAddresses);
        for (String key : map.keySet()){
            int index = key.indexOf("/");
            String firstIp = key.substring(0, index);
            int firstMask = Integer.parseInt(key.substring(index + 1));
            // 插入本地数据库 and 同步ipam
            // 插如一级ip网段
            Long firstSubnetId = null;
            Subnet firstSubnet = this.zabbixSubnetService.selectObjByIp(firstIp, firstMask);
            if(firstSubnet != null){
                firstSubnetId = firstSubnet.getId();
            }
            if(firstSubnet == null){
                Subnet subnet = new Subnet();
                subnet.setIp(IpUtil.ipConvertDec(firstIp));
                subnet.setMask(firstMask);
                this.zabbixSubnetService.save(subnet);
                firstSubnetId = subnet.getId();
            }
            // 获取二级网段
            JSONArray array = JSONArray.parseArray(JSON.toJSONString(map.get(key)));
            for (Object obj : array) {
                if(obj instanceof String){
                    String second = ((String) obj).trim();
                    int sequence = second.indexOf("/");
                    String ip = second.substring(0, sequence);
                    int secondMask = Integer.parseInt(second.substring(sequence + 1));
                    Subnet secondSubnet = this.zabbixSubnetService.selectObjByIp(ip, secondMask);
                    if(secondSubnet == null){
                        Subnet subnet = new Subnet();
                        subnet.setIp(IpUtil.ipConvertDec(ip));
                        subnet.setMask(secondMask);
                        subnet.setParentIp(IpUtil.ipConvertDec(firstIp));
                        subnet.setParentId(firstSubnetId);
                        this.zabbixSubnetService.save(subnet);
                    }
                }
                if(obj instanceof JSONObject){
                    JSONObject object = (JSONObject) obj;
                    for (String okey : object.keySet()){
                        String second = ((String) okey).trim();
                        int sequence = second.indexOf("/");
                        String secondIp = second.substring(0, sequence);
                        int secondMask = Integer.parseInt(second.substring(sequence + 1));
                        Long secondSubnetId = null;
                        Subnet secondSubnet = this.zabbixSubnetService.selectObjByIp(secondIp, secondMask);
                        if(secondSubnet != null){
                            secondSubnetId = secondSubnet.getId();
                        }
                        if(secondSubnet == null){
                            Subnet subnet = new Subnet();
                            subnet.setIp(IpUtil.ipConvertDec(secondIp));
                            subnet.setMask(secondMask);
                            subnet.setParentIp(IpUtil.ipConvertDec(firstIp));
                            subnet.setParentId(firstSubnetId);
                            this.zabbixSubnetService.save(subnet);
                            secondSubnetId = subnet.getId();
                        }
                        JSONArray thirdArray = JSONArray.parseArray(object.get(okey).toString());
                        for (Object thirdKey : thirdArray) {
                            if(obj instanceof JSONObject){
                                String third = ((String) thirdKey).trim();
                                int thirdSequence = third.indexOf("/");
                                String thirdIp = third.substring(0, thirdSequence);
                                int thirdMask = Integer.parseInt(third.substring(thirdSequence + 1));
                                Subnet thirdSubnet = this.zabbixSubnetService.selectObjByIp(thirdIp, thirdMask);
                                if(thirdSubnet == null){
                                    Subnet subnet = new Subnet();
                                    subnet.setIp(IpUtil.ipConvertDec(thirdIp));
                                    subnet.setMask(thirdMask);
                                    subnet.setParentIp(IpUtil.ipConvertDec(secondIp));
                                    subnet.setParentId(secondSubnetId);
                                    this.zabbixSubnetService.save(subnet);
                                }
                            }
                        }
                    }
                }
            }
        }
        // 同步子网ip
        // 获取所有子网一级
        List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(null);

        List<IpDetail> ipdetails = this.ipDetailService.selectObjByMap(null);
        if(subnets.size() > 0) {
            ExecutorService exe = Executors.newFixedThreadPool(subnets.size());
            exe.execute(new Runnable() {
                @Override
                public void run() {
                    for (IpDetail ipDetail : ipdetails) {
                        if (ipDetail.getIp() != null) {
                            if (ipDetail.getIp().equals("0.0.0.0")) {
                                continue;
                            }
                            String ip = IpUtil.decConvertIp(Long.parseLong(ipDetail.getIp()));
                            if (!IpUtil.verifyIp(ip)) {
                                continue;
                            }
                            // 判断ip地址是否属于子网
                            for (Subnet subnet : subnets) {
                                genericNoSubnet(subnet, ipDetail);
                            }
                        }
                    }
                }
            });
        }
        return ResponseUtil.ok();
    }

    @RequestMapping("/list")
    public Object list(){
        // 获取所有子网一级
        List<Subnet> parentList = this.zabbixSubnetService.selectSubnetByParentId(null);
        if(parentList.size() > 0){
            for (Subnet subnet : parentList) {
                this.genericSubnet(subnet);
            }
            return ResponseUtil.ok(parentList);
        }
        return ResponseUtil.ok();
    }

    public List<Subnet> genericSubnet(Subnet subnet){
        List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(subnet.getId());
        if(subnets.size() > 0){
            for(Subnet child : subnets){
                List<Subnet> subnetList = genericSubnet(child);
                if(subnetList.size() > 0){
                    child.setSubnetList(subnetList);
                }
            }
            subnet.setSubnetList(subnets);
        }
        return subnets;
    }

    @GetMapping("/add")
    public Object add(){
        List<Domain> domains = this.domainService.selectDomainAndVlanByMap(null);
        return ResponseUtil.ok(domains);
    }

    /**
     * 网段编辑topology
     * @param
     * @return
     */
    @GetMapping("/update")
    public Object update(@RequestParam Long id){
        Subnet subnet = this.zabbixSubnetService.selectObjById(id);
        if(subnet.getVlanId() != null){
            Vlan vlan = vlanService.selectObjById(subnet.getVlanId());
            if(vlan != null){
                subnet.setVlanId(vlan.getId());
                subnet.setVlanName(vlan.getName());
            }
        }
        List<Domain> domains = this.domainService.selectDomainAndVlanByMap(null);
        Map map = new HashMap();
        map.put("domains", domains);
        map.put("subnet", subnet);
        return ResponseUtil.ok(map);
    }

    @ApiOperation("网段编辑")
    @PostMapping
    public Object save(@RequestBody Subnet subnet){
        if(subnet.getId() == null){
            return ResponseUtil.badArgument("不允许创建网段");
        }
        if(subnet.getIp() != null && !subnet.getIp().equals("")){
            return ResponseUtil.badArgument("网段ip不可编辑");
        }
        if(subnet.getVlanId() != null){
            Vlan vlan = vlanService.selectObjById(subnet.getVlanId());
            if(vlan != null){
                subnet.setVlanId(vlan.getId());
                subnet.setVlanName(vlan.getName());
            }
        }
        int i = this.zabbixSubnetService.update(subnet);
        if(i >= 1){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.error();
        }
    }

    // 编辑网段
//    @PostMapping
//    public Object save(@RequestBody Subnet subnet){
//        // 校验Ip地址格式
//        if(StringUtil.isEmpty(subnet.getIp())){
//            return ResponseUtil.badArgument("以CIDR格式输入子网");
//        }else{
//            if(!IpUtil.verifyIp(subnet.getIp())){
//                return ResponseUtil.badArgument("错误的CIDR格式");
//            }
//        }
//        if(subnet.getMask() == null ){
//            return ResponseUtil.badArgument("以CIDR格式输入子网");
//        }else if(subnet.getMask() > 32 || subnet.getMask() < 0){
//            return ResponseUtil.badArgument("错误的CIDR格式");
//        }
//        // 校验Ip地址不能为子网，并返回子网信息（IP address cannot be subnet! (Consider using 59.51.2.0)）
//        String mask = IpUtil.bitMaskConvertMask(subnet.getMask());
//        Map SubnetMap = IpUtil.getNetworkIp(subnet.getIp(), mask);
//        String network = SubnetMap.get("network").toString();
//        if(!subnet.getIp().equals(network)){
//            return ResponseUtil.badArgument("Ip地址不能为子网!(考虑使用：" + network + ")");
//        }
//        // 如果主子网不为空。判断子网是否属于主子网
//        // Subnet is not within boundaries of its master subnet
//
//        if(subnet.getParentId() != null){
//            Subnet parentSbunet = this.zabbixSubnetService.selectObjById(subnet.getParentId());
//            // 此处IP为网段
//            boolean flag = IpUtil.ipIsInNet(subnet.getIp(), parentSbunet.getIp()+"/"+parentSbunet.getMask());
//            if(!flag){
//                return ResponseUtil.badArgument("子网不在其主子网的边界内");
//            }
//        }
//
//        return null;
//    }

    @ApiOperation("根据网段Ip查询直接从属子网")
    @GetMapping(value = {"","/{id}"})
    public Object getSubnet(@PathVariable(value = "id", required = false) Long id){
        if(id == null){
            // 获取所有子网一级
            List<Subnet> parentList = this.zabbixSubnetService.selectSubnetByParentId(null);
            if(parentList.size() > 0){
                for (Subnet subnet : parentList) {
                    this.genericSubnet(subnet);
                }
                return ResponseUtil.ok(parentList);
            }
        }else{
            // 校验子网是否存在
            Subnet subnet = this.zabbixSubnetService.selectObjById(id);
            if(subnet != null){
                // 当前网段
                Map map = new HashMap();
                map.put("subnet", subnet);
                // 获取从子网列表
                List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(id);
                //
                map.put("subnets", subnets);
                // 查询IP addresses in subnets
                if(subnets.size() <= 0 && subnet.getMask() >= 21){
                    // 获取地址列表
                    // 获取最大Ip地址和最小Ip地址
                    String mask = IpUtil.bitMaskConvertMask(subnet.getMask());
                    Map networkMap = IpUtil.getNetworkIp(subnet.getIp(), mask);
                    String[] ips = IpUtil.getSubnetList(networkMap.get("network").toString(),
                            subnet.getMask());
                    if(ips.length > 0){
                        Map addresses = new LinkedHashMap();
                        for(String ip : ips){
                            Address address = this.addressService.selectObjByIp(IpUtil.ipConvertDec(ip));
                            if(address != null){
                                IpDetail ipDetail = this.ipDetailService.selectObjByIp(IpUtil.ipConvertDec(ip));
                                int time = ipDetail.getTime();
                                int day = time / 24;
                                int time1 = time % 24;
                                ipDetail.setDuration(day + "天" + time1 + "小时");
                                address.setIpDetail(ipDetail);
                            }
                            addresses.put(ip, address);
                        }
                        map.put("addresses", addresses);
                    }
                }else{
                    // 查询子网ip地址列表
                    Map params = new HashMap();
                    params.put("subnetId", subnet.getId());
                    List<Address> address = this.addressService.selectObjByMap(params);
                    map.put("mastSubnetAddress", address);
                }
                return ResponseUtil.ok(map);
            }
            return ResponseUtil.badArgument("网段不存在");
        }
        return ResponseUtil.ok();
    }

    @ApiOperation("删除网段")
    @DeleteMapping
    public Object delete(@RequestParam(value = "id") Long id){
        Subnet subnet = this.zabbixSubnetService.selectObjById(id);
        if(subnet != null){
            // 查询子网ip地址列表
            Map params = new HashMap();
            params.put("subnetId", subnet.getId());
            List<Address> address = this.addressService.selectObjByMap(params);
            for (Address obj : address){
                this.addressService.delete(obj.getId());
            }
//            // 递归删除所有ip
            try {
                this.genericDel(subnet);
            } catch (Exception e) {
                e.printStackTrace();
            }
//            List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(subnet.getId());
//            for (Subnet obj : subnets){
//                params.clear();
//                params.put("subnetId", obj.getId());
//                List<Address> addresses = this.addressService.selectObjByMap(params);
//                for (Address address1 : addresses){
//                    this.addressService.delete(address1.getId());
//                }
//                this.zabbixSubnetService.delete(obj.getId());
//            }
            // 批量
//            if(subnet != null){
//                this.genericSubnet(subnet);
//            }
//            this.zabbixSubnetService.delete(id);
        }
        return ResponseUtil.ok();
    }


    public void genericDel(Subnet subnet){
        List<Subnet> childs = this.zabbixSubnetService.selectSubnetByParentId(subnet.getId());
        if(childs.size() > 0){
            for(Subnet child : childs){
                genericDel(child);
            }
        }
        Map params = new HashMap();
        params.clear();
        params.put("subnetId", subnet.getId());
        List<Address> addresses = this.addressService.selectObjByMap(params);
        for (Address address : addresses){
            this.addressService.delete(address.getId());
        }
        this.zabbixSubnetService.delete(subnet.getId());
    }

    @GetMapping("/address")
    public Object subnet(){
        // 获取所有子网一级
        List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(null);
        List<IpDetail> ipdetails = this.ipDetailService.selectObjByMap(null);
            if(subnets.size() > 0){
                for(IpDetail ipDetail : ipdetails){
                    if(ipDetail.getIp().equals("0.0.0.0")){
                        continue;
                    }
                    String ip = IpUtil.decConvertIp(Long.parseLong(ipDetail.getIp()));
                    if(!IpUtil.verifyIp(ip)){
                        continue;
                    }
                    // 判断ip地址是否属于子网
                    for(Subnet subnet : subnets){
                        genericNoSubnet(subnet, ipDetail);
                    }
                }
            }
        return null;
    }

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

    @ApiOperation("Ip使用率")
    @GetMapping("/picture2")
    public Object picture2(){
        // 根据子网查询address
        List subnetList = new ArrayList();
        List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(null);
        for(Subnet subnet : subnets){
            Set<Long> ids = this.genericSubnet(subnet.getId());
            Map params = new HashMap();
            if(ids.size() > 0){
                params.clear();
                params.put("subnetIds", ids);
                List<Address> addresses = this.addressService.selectObjByMap(params);
                if(addresses.size() > 0){
                    List<String> ips = new ArrayList<>();
                    addresses.forEach((item) -> {
                        ips.add(IpUtil.ipConvertDec(item.getIp()));
                    });
                    params.clear();
                    params.put("ips", ips);
                    params.put("usage", 0);
                    List<IpDetail> unuseds = this.ipDetailService.selectObjByMap(params);
                    params.clear();
                    params.put("ips", ips);
                    params.put("start", 1);
                    params.put("end", 2);
                    List<IpDetail> seldom = this.ipDetailService.selectObjByMap(params);
                    params.clear();
                    params.put("ips", ips);
                    params.put("start", 3);
                    params.put("end", 9);
                    List<IpDetail> unmeant = this.ipDetailService.selectObjByMap(params);
                    params.clear();
                    params.put("ips", ips);
                    params.put("endUsage", 10);
                    List<IpDetail> regular = this.ipDetailService.selectObjByMap(params);
                    List<Integer> list = this.genericSubnetIps(subnet.getId());
                    IntSummaryStatistics summaryStatistics = list.stream().mapToInt((s) -> (int) s).summaryStatistics();
                    int sum = (int) summaryStatistics.getSum();
                    int existingSum = unuseds.size() + seldom.size() + unmeant.size() + regular.size();
                    int inexistenceSum = sum - existingSum;

                    float unusedScale =(float)(unuseds.size() + inexistenceSum) / sum;
                    Map map = new HashMap();
                    map.put("unused",  Math.round(unusedScale * 100));
                    float seldomScale =(float)seldom.size() / sum;
                    map.put("seldom", Math.round(seldomScale * 100));
                    float unmeantScale =(float)unmeant.size() / sum;
                    map.put("unmeant", Math.round(unmeantScale * 100));
                    float regularScale =(float)regular.size() / sum;
                    map.put("regular", Math.round(regularScale * 100));
                    subnetList.add(subnet.setPicture(map));
                }
            }
        }
        return ResponseUtil.ok(subnetList);
    }

    @ApiOperation("Ip使用率")
    @GetMapping("/picture")
    public Object picture(@RequestParam(value = "subnetId", required = false) Long subnetId){
        // 根据子网查询address
        Set<Long> subnetIds = new HashSet<>();
        if(subnetId != null){
            Set<Long> ids = this.genericSubnet(subnetId);
            subnetIds.addAll(ids);
        }
        Map params = new HashMap();
        if(subnetIds.size() > 0){
            params.clear();
            params.put("subnetIds", subnetIds);
            List<Address> addresses = this.addressService.selectObjByMap(params);
            if(addresses.size() > 0){
                List<String> ips = new ArrayList<>();
                addresses.forEach((item) -> {
                    ips.add(IpUtil.ipConvertDec(item.getIp()));
                });
                params.clear();
                params.put("ips", ips);
                params.put("usage", 0);
                List<IpDetail> unuseds = this.ipDetailService.selectObjByMap(params);
                params.clear();
                params.put("ips", ips);
                params.put("start", 1);
                params.put("end", 2);
                List<IpDetail> seldom = this.ipDetailService.selectObjByMap(params);
                params.clear();
                params.put("ips", ips);
                params.put("start", 3);
                params.put("end", 9);
                List<IpDetail> unmeant = this.ipDetailService.selectObjByMap(params);
                params.clear();
                params.put("ips", ips);
                params.put("endUsage", 10);
                List<IpDetail> regular = this.ipDetailService.selectObjByMap(params);
                List<Integer> list = this.genericSubnetIps(subnetId);
                IntSummaryStatistics summaryStatistics = list.stream().mapToInt((s) -> (int) s).summaryStatistics();
                int sum = (int) summaryStatistics.getSum();
                int existingSum = unuseds.size() + seldom.size() + unmeant.size() + regular.size();
                int inexistenceSum = sum - existingSum;

                float unusedScale =(float)(unuseds.size() + inexistenceSum) / sum;
                Map map = new HashMap();
                map.put("unused",  Math.round(unusedScale * 100));

                float seldomScale =(float)seldom.size() / sum;

                map.put("seldom", Math.round(seldomScale * 100));

                float unmeantScale =(float)unmeant.size() / sum;

                map.put("unmeant", Math.round(unmeantScale * 100));

                float regularScale =(float)regular.size() / sum;

                map.put("regular", Math.round(regularScale * 100));

                return ResponseUtil.ok(map);
            }
        }

        return ResponseUtil.ok();
    }



    /**
     * 获取所有从属子网Id
     * @param id
     * @return
     */
    public Set<Long> genericSubnet(Long id){
        Set<Long> ids = new HashSet();
        Subnet subnet = this.zabbixSubnetService.selectObjById(id);
        if(subnet != null){
            ids.add(id);
            List<Subnet> childs = this.zabbixSubnetService.selectSubnetByParentId(subnet.getId());
            if(childs.size() > 0){
                for (Subnet obj : childs){
                    Set<Long> cids = genericSubnet(obj.getId());
                    ids.addAll(cids);
                    ids.add(obj.getId());
                }
            }
        }
        return ids;
    }

    /**
     * 获取从属子网ips
     * @param id
     * @return
     */
    public List<Integer> genericSubnetIps(Long id){
        List<Integer> list = new ArrayList();
        Subnet subnet = this.zabbixSubnetService.selectObjById(id);
        if(subnet != null){
            // 从属子网
            List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(subnet.getId());
            if(subnets.size() > 0){
                for (Subnet obj : subnets){
                    List<Integer> clengs = genericSubnetIps(obj.getId());
                    list.addAll(clengs);
                    List<Subnet> csunets = this.zabbixSubnetService.selectSubnetByParentId(subnet.getId());
                    // 查询IP addresses in subnets
                    if(csunets.size() <= 0 && obj.getMask() >= 21){
                        // 获取地址列表
                        // 获取最大Ip地址和最小Ip地址
                        String mask = IpUtil.bitMaskConvertMask(obj.getMask());
                        Map networkMap = IpUtil.getNetworkIpDec(obj.getIp(), mask);
                        String[] ips = IpUtil.getSubnetList(networkMap.get("network").toString(),
                                obj.getMask());
                        if(ips.length > 0){
                            list.add(ips.length);
                        }
                    }
                }
            }
            // 查询IP addresses in subnets
            if(subnets.size() <= 0 && subnet.getMask() >= 21){
                // 获取地址列表
                // 获取最大Ip地址和最小Ip地址
                String mask = IpUtil.bitMaskConvertMask(subnet.getMask());
                Map networkMap = IpUtil.getNetworkIp(subnet.getIp(), mask);
                String[] ips = IpUtil.getSubnetList(networkMap.get("network").toString(),
                        subnet.getMask());
                if(ips.length > 0){
                    list.add(ips.length);
                }
            }
        }
        return list;
    }
}
