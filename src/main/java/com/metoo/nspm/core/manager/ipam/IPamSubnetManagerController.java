package com.metoo.nspm.core.manager.ipam;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.http.IpamApiUtil;
import com.metoo.nspm.core.service.phpipam.IpamSectionService;
import com.metoo.nspm.core.service.phpipam.IpamSubnetService;
import com.metoo.nspm.core.service.phpipam.IpamVlanService;
import com.metoo.nspm.core.service.nspm.IpDetailService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.entity.Ipam.IpamSubnet;
import com.metoo.nspm.entity.nspm.IpDetail;
import com.github.pagehelper.util.StringUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Api("IPAM-子网")
@RequestMapping("/ipam/subnet")
@RestController
public class IPamSubnetManagerController {


    @Autowired
    private IpamSubnetService ipamSubnetService;
    @Autowired
    private IpamVlanService ipamVlanService;
    @Autowired
    private IpamSectionService ipamSectionService;
    @Autowired
    private IpDetailService ipDetailService;

    @ApiOperation("子网列表")
    @GetMapping(value = {"/subnets/{id}", "/subnets"})
    public Object subnets(@PathVariable(required = false) Integer id){
        JSONObject result = this.ipamSubnetService.subnets(id, null);
        if(result != null && result.getBoolean("success")){
            Object data = result.get("data");
            // 递归获取数据等级
            if(data instanceof JSONArray){
                JSONArray array = JSONArray.parseArray(data.toString());
                List<JSONObject> subnets = this.recursion(array);
                // 排序
                for(JSONObject subnet : subnets){
                    List<JSONObject> list = subnet.getObject("child", List.class);
                    for(JSONObject child : list){
                        List<JSONObject> childs = child.getObject("child", List.class);
                        SortedSet set = this.sortSubnet(childs);
                        child.put("child", set);
                    }
                    SortedSet set = this.sortSubnet(list);
                    subnet.put("child", set);
                }
                SortedSet set = this.sortSubnet(subnets);
                return ResponseUtil.ok(set);
            }
            if(data instanceof JSONObject){
                JSONObject subnet = JSONObject.parseObject(data.toString());
                if(subnet.getInteger("vlanId") != null){
                    Object obj = this.ipamVlanService.vlan(subnet.getInteger("vlanId"));
                    if(obj != null){
                        JSONObject vlan = JSONObject.parseObject(obj.toString());
                        subnet.put("vlanName", vlan.getString("name"));
                    }
                }
                // 使用率
                Object usage = this.ipamSubnetService.subnets(id, "usage");
                if(usage != null){
                    JSONObject obj = JSONObject.parseObject(usage.toString());
                    subnet.put("usage", obj);
                }
                return ResponseUtil.ok(subnet);
            }
        }
        return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
    }

    public Long toNumeric(String ip) {
        Scanner sc = new Scanner(ip).useDelimiter("\\.");
        Long l = (sc.nextLong() << 24) + (sc.nextLong() << 16) + (sc.nextLong() << 8)
                + (sc.nextLong());

        sc.close();
        return l;
    }

    public SortedSet sortSubnet(List<JSONObject> list){
        Comparator<JSONObject> ipComparator = new Comparator<JSONObject>() {
            @Override
            public int compare(JSONObject obj1, JSONObject obj2) {
                String ip1 = obj1.getString("subnet");
                String ip2 = obj2.getString("subnet");
                return toNumeric(ip1).compareTo(toNumeric(ip2));
            }
        };
        SortedSet<JSONObject> ips = new TreeSet<JSONObject>(ipComparator);
        for (JSONObject object : list){
            ips.add(object);
        }
        return ips;
    }


    public List<JSONObject> recursion(JSONArray datas){
        List list = new ArrayList();
        for (Object obj : datas){
            JSONObject data = JSONObject.parseObject(obj.toString());
            if(data.getString("masterSubnetId").equals("0")){
                List list2 = new ArrayList();
                for (Object obj2 : datas){
                    JSONObject data2 = JSONObject.parseObject(obj2.toString());
                    if(data2.getString("masterSubnetId").equals(data.getString("id"))){
                        list2.add(data2);
                        List list3 = new ArrayList();
                        for (Object obj3 : datas){
                            JSONObject data3 = JSONObject.parseObject(obj3.toString());
                            if(data3.getString("masterSubnetId").equals(data2.getString("id"))){
                                data2.put("child", data3);
                                list3.add(data3);
                            }
                        }
                        data2.put("child", list3);
                    }
                }
                data.put("child", list2);
                list.add(data);
            }
        }
        return list;
    }

    @ApiOperation("从属子网")
    @GetMapping(value = {"/subnets/{id}/slaves_recursive"})
    public Object slaves_recursive(@PathVariable(required = false) Integer id){
        JSONObject result = this.ipamSubnetService.subnets(id, "slaves_recursive");
        if(result != null && result.getBoolean("success")){
            // 获取最大Ip和最小Ip，根据ip的地址获取ip信息
            if(!StringUtil.isEmpty(result.getString("data"))){
                JSONArray datas = JSONObject.parseArray(result.getString("data"));
                if(datas.size() > 0){
                    JSONObject data = JSONObject.parseObject(datas.getString(0));
                    if (!StringUtil.isEmpty(data.getString("calculation"))){
                        JSONObject calculation = JSONObject.parseObject(data.getString("calculation"));
                        String subnetMask = calculation.getString("Subnet bitmask");
                        if(Integer.parseInt(subnetMask) >= 24){
                            String[] ips = IpUtil.getSubnetList(calculation.getString("Max host IP"),
                                    calculation.getInteger("Subnet bitmask"));
                            if(ips != null && ips.length > 0){
                                String subnetId = data.getString("id");
                                String url = "/subnets/";
                                if(subnetId != null){
                                    url += subnetId + "/addresses";
                                }
                                IpamApiUtil base = new IpamApiUtil(url);
                                JSONObject subnetAddresses = base.get();
                                JSONArray addressDatas = null;
                                if(subnetAddresses != null && subnetAddresses.getBoolean("success")) {
                                    addressDatas = JSONArray.parseArray(subnetAddresses.getString("data"));
                                }
                                Map map = new LinkedHashMap();
                                for(String ip : ips){
                                    // 根据Ip查询子网是否存在，
                                    // 不存在：不查询ip信息（使用率，在线时长）
                                    // 存在： 显示子网信息，以及ip信息
                                    Map addressMap = new HashMap();
                                    if(addressDatas != null){
                                        for(Object obj : addressDatas){
                                            JSONObject object = JSONObject.parseObject(obj.toString());
                                            if(object.getString("ip").equals(ip)){
                                                IpDetail ipDetail = ipDetailService.selectObjByIp(IpUtil.ipConvertDec(ip));
                                                addressMap.put("ipDetail", ipDetail);
                                                addressMap.put("subnetId", subnetId);
                                                addressMap.put("id", object.getString("id"));
                                                addressMap.put("ip", object.getString("ip"));
                                                addressMap.put("description", object.getString("description"));
                                                addressMap.put("mac", object.getString("mac"));
                                                addressMap.put("hostname", object.getString("hostname"));
                                                map.put(ip, addressMap);
                                            }
                                        }
                                    }

                                    if(addressMap.isEmpty()){
                                        IpDetail ipDetail = ipDetailService.selectObjByIp(IpUtil.ipConvertDec(ip));
                                        addressMap.put("ipDetail", ipDetail);
                                        map.put(ip, addressMap);
                                    }
                                }
                                data.put("subnets", map);
                            }
                        }
                    }
                    return  ResponseUtil.ok(data);
                }
            }
            return  ResponseUtil.ok();
        }
        return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
    }


    @ApiOperation("从属子网")
    @GetMapping(value = {"/subnets/v3/{id}/slaves_recursive"})
    public Object slaves_recursiveV3(@PathVariable(required = false) Integer id){
        JSONObject result = this.ipamSubnetService.subnets(id, "slaves_recursive");
        if(result != null && result.getBoolean("success")){
            // 获取最大Ip和最小Ip，根据ip的地址获取ip信息
            if(!StringUtil.isEmpty(result.getString("data"))){
                JSONArray datas = JSONObject.parseArray(result.getString("data"));
                if(datas.size() > 0){
                    JSONObject data = JSONObject.parseObject(datas.getString(0));
                    if (!StringUtil.isEmpty(data.getString("calculation"))){
                        JSONObject calculation = JSONObject.parseObject(data.getString("calculation"));
                        String[] ips = IpUtil.getSubnetList(calculation.getString("Max host IP"), calculation.getInteger("Subnet bitmask"));
                        ExecutorService exe = null;
                        if(ips != null && ips.length > 0){
                            exe = Executors.newFixedThreadPool(ips.length);
                            String subnetId = data.getString("id");
                            Map map = new LinkedHashMap();
                            for(String ip : ips){
                                exe.execute(new Thread(new Runnable() {

                                    @Override
                                    public void run() {
                                        // 根据Ip查询子网是否存在，
                                        // 不存在：不查询ip信息（使用率，在线时长）
                                        // 存在： 显示子网信息，以及ip信息
                                        String url = "/addresses/";
                                        if(ip != null){
                                            url +=  ip;
                                        }
                                        if(subnetId != null){
                                            url += "/" + subnetId;
                                        }
                                        IpamApiUtil base = new IpamApiUtil(url);
                                        JSONObject addresses = base.get();
                                        if(addresses != null && addresses.getBoolean("success")) {
                                            JSONObject addressData = JSONObject.parseObject(addresses.getString("data"));
                                            Map addressMap = new HashMap();
                                            IpDetail ipDetail = ipDetailService.selectObjByIp(IpUtil.ipConvertDec(ip));
                                            addressMap.put("ipDetail", ipDetail);
                                            addressMap.put("ip", addressData.getString("ip"));
                                            addressMap.put("description", addressData.getString("description"));
                                            addressMap.put("mac", addressData.getString("mac"));
                                            addressMap.put("hostname", addressData.getString("hostname"));
                                            map.put(ip, addressMap);
                                        }
                                    }
                                }));
                            }
                            if(exe != null){
                                exe.shutdown();
                            }
                            while (true) {
                                if (exe == null || exe.isTerminated()) {
                                    data.put("subnets", map);
                                    break;
                                }
                            }
                        }
                    }
                    return  ResponseUtil.ok(data);
                }
            }
            return  ResponseUtil.ok();
        }
        return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
    }

    @ApiOperation("从属子网")
    @GetMapping(value = {"/subnets/v2/{id}/slaves_recursive"})
    public Object slaves_recursiveV2(@PathVariable(required = false) Integer id){
        JSONObject result = this.ipamSubnetService.subnets(id, "slaves_recursive");
        if(result != null && result.getBoolean("success")){
            // 获取最大Ip和最小Ip，根据ip的地址获取ip信息
            if(!StringUtil.isEmpty(result.getString("data"))){
                JSONArray datas = JSONObject.parseArray(result.getString("data"));
                if(datas.size() > 0){
                    JSONObject data = JSONObject.parseObject(datas.getString(0));
                    if (!StringUtil.isEmpty(data.getString("calculation"))){
                        JSONObject calculation = JSONObject.parseObject(data.getString("calculation"));
                        String[] ips = IpUtil.getSubnetList(calculation.getString("Max host IP"), calculation.getInteger("Subnet bitmask"));
                        if(ips != null){
                            Map map = new LinkedHashMap();
                            for(String ip : ips){
                                // 根据Ip查询子网是否存在
                                // 不存在：不查询ip信息（使用率，在线时长）
                                // 存在： 显示子网信息，以及ip信息
//                                this.ipamSubnetService.getSubnetsBySubnet(ip, mask);
                                IpDetail ipDetail = this.ipDetailService.selectObjByIp(IpUtil.ipConvertDec(ip));
                                map.put(ip, ipDetail);
                            }
                            data.put("subnets", map);
                        }
                    }
                    return  ResponseUtil.ok(data);
                }
            }
            return  ResponseUtil.ok();
        }
        return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
    }


    @ApiOperation("子网地址")
    @GetMapping(value = {"/subnets/{id}/{path}"})
    public Object subnet(@PathVariable(value = "id", required = false) Integer id,
                         @PathVariable(value = "path", required = false) String path){
        JSONObject result = this.ipamSubnetService.subnets(id, path);
        if(result != null && result.getBoolean("success")){
            Object data = result.get("data");
            return  ResponseUtil.ok(data);
        }
        return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
    }

    @ApiOperation("Searches for subnet in CIDR format")
    @GetMapping(value = {"/subnets/search/{subnet}/{mask}"})
    public Object search(@PathVariable(value = "subnet", required = false) String subnet,
                         @PathVariable(value = "mask", required = false) Integer mask){
        return this.ipamSubnetService.getSubnetsBySubnet(subnet, mask);
    }

    @ApiOperation("子网添加")
    @PostMapping(value = {"/subnets"})
    public Object create(@RequestBody IpamSubnet subnet){
        // 获取默认标签
        JSONObject section = this.ipamSectionService.sections(null, null);
        if(section.getBoolean("success")){
            JSONArray datas = JSONArray.parseArray(section.getString("data"));
            if(datas.size() > 0){
                JSONObject data = JSONObject.parseObject(datas.getString(0));
                Integer id = data.getInteger("id");
                subnet.setSectionId(id);
            }

        }
        JSONObject result = this.ipamSubnetService.create(subnet);
        if(result.getBoolean("success")){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
        }
    }

    @ApiOperation("子网更新")
    @PatchMapping(value = {"/subnets"})
    public Object update(@RequestBody IpamSubnet subnet){
        JSONObject result = this.ipamSubnetService.update(subnet);
        if(result != null){
            if(result.getBoolean("success")){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
            }
        }
        return ResponseUtil.error();
    }

    @ApiOperation("子网删除")
    @DeleteMapping(value = {"/subnets/{id}/{path}", "/subnets/{id}"})
    public Object del(@PathVariable(value = "id", required = false) Integer id,
                      @PathVariable(value = "path", required = false) String path){
        JSONObject result = this.ipamSubnetService.remove(id, path);
        if(result.getBoolean("success")){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
        }
    }


}
