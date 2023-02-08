package com.metoo.nspm.core.manager.ipam;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.http.IpamApiUtil;
import com.metoo.nspm.core.service.phpipam.IpamAddressService;
import com.metoo.nspm.core.service.nspm.IpDetailService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.Ipam.IpamAddress;
import com.metoo.nspm.entity.nspm.IpDetail;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequestMapping("/ipam")
@RestController
public class IpamAddressManagerController {

    @Autowired
    private IpamAddressService ipamAddressService;
    @Autowired
    private IpDetailService ipDetailService;

    public static void main(String[] args) {

        int a = 10;
        int b = 50;
        float num =(float)a/b;
        DecimalFormat df = new DecimalFormat("0.0");
        String  result = df.format(num);
        System.out.println(result);
    }

//    @GetMapping(value = {"/addresses/{id}/{path}", "/addresses/{id}", "/addresses"})
//    public Object addresses(@PathVariable(value = "id", required = false) Integer id,
//                        @PathVariable(value = "path", required = false) String path){
//        JSONObject result = this.ipamAddressService.addresses(id, path);
//        if(result != null && result.getBoolean("success")) {
//            Object data = result.get("data");
//            if(data instanceof JSONObject){
//                JSONObject subnet = JSONObject.parseObject(data.toString());
//                // 查询是否已存在pi地址
//                IpDetail ipDetail = this.ipDetailService.selectObjByIp(((JSONObject) data).getString("ip"));
//                if(ipDetail != null){
//                    subnet.put("line", ipDetail.isLine());
//                    subnet.put("time", ipDetail.getTime());
//                    subnet.put("usage", ipDetail.getUsage());
////                    IpDetail init = this.ipDetailService.selectObjByIp("0.0.0.0");
////                    float num =(float)ipDetail.getTime() / init.getTime();
////                    int usage = Math.round(num * 100);
////                    DecimalFormat df = new DecimalFormat("0.00");
////                    String usage = df.format(num * 100);
////                    subnet.put("usage", usage );
//                }
//                return ResponseUtil.ok(subnet);
//            }
//            return ResponseUtil.ok(data);
//        }
//        return ResponseUtil.ok();
//    }

    @GetMapping(value = {"/addresses/{id}", "/addresses/{ip}/{subnetId}"})
    public Object objByIpSubnetId(@PathVariable(value = "id", required = false) Integer id,
                                  @PathVariable(value = "ip", required = false) String ip,
                                  @PathVariable(value = "subnetId", required = false) Integer subnetId){
        String url = "/addresses/";
        if(id != null){
            url +=  id;
        }
        if(ip != null){
            url +=  ip;
        }
        if(subnetId != null){
            url += "/" + subnetId;
        }
        IpamApiUtil base = new IpamApiUtil(url);
        JSONObject result = base.get();
        if(result != null && result.getBoolean("success")) {
            Object data = result.get("data");
            if(data instanceof JSONObject){
                JSONObject subnet = JSONObject.parseObject(data.toString());
                // 查询是否已存在pi地址
                    ip = subnet.getString("ip");
                    IpDetail ipDetail = this.ipDetailService.selectObjByIp(ip);
                    if(ipDetail != null){
                        subnet.put("online", ipDetail.isOnline());
                        subnet.put("time", ipDetail.getTime());
                        subnet.put("usage", ipDetail.getUsage());
                    }
                }
                return ResponseUtil.ok(data);
            }
        IpDetail ipDetail = this.ipDetailService.selectObjByIp(ip);
        if(ipDetail != null){
            Map map = new HashMap();
            map.put("online", ipDetail.isOnline());
            map.put("time", ipDetail.getTime());
            map.put("usage", ipDetail.getUsage());
            return ResponseUtil.ok(map);
        }
        return ResponseUtil.ok();
    }

    // ip使用率
    @GetMapping("/picture")
    public Object picture(){
        Map params = new HashMap();
        params.put("usage", 0);
        List<IpDetail> unused = this.ipDetailService.selectObjByMap(params);
        params.clear();
        params.put("start", 1);
        params.put("end", 2);
        List<IpDetail> seldom = this.ipDetailService.selectObjByMap(params);
        params.clear();
        params.put("start", 3);
        params.put("end", 9);
        List<IpDetail> unmeant = this.ipDetailService.selectObjByMap(params);
        params.clear();
        params.put("endUsage", 10);
        List<IpDetail> regular = this.ipDetailService.selectObjByMap(params);
        int sum = unused.size() + seldom.size() + unmeant.size() + regular.size();

        float unusedScale =(float)unused.size() / sum;

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

    @ApiOperation("")
    @PostMapping(value = {"/addresses"})
    public Object save(@RequestBody IpamAddress instance){
        JSONObject result = this.ipamAddressService.create(instance);
        if(result != null){
            if(result.getBoolean("success")){
                // 同步更新到metoo数据库
//                IpDetail ipDetail = new IpDetail();
//                ipDetail.setId(instance.getIpDetailId());
//                ipDetail.setDeviceName(instance.getHostname());
//                ipDetail.setIp(instance.getIp());
//                ipDetail.setDescription(instance.getDescription());
//                ipDetail.setMac(instance.getMac());
//                try {
//                    this.ipDetailService.save(ipDetail);
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
            }
        }
        return ResponseUtil.error();
    }

    @ApiOperation("")
    @PatchMapping(value = {"/addresses"})
    public Object update(@RequestBody IpamAddress instance){
        JSONObject result = this.ipamAddressService.update(instance);
        if(result != null){
            if(result.getBoolean("success")){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
            }
        }
        return ResponseUtil.error();
    }

    @ApiOperation("")
    @DeleteMapping(value = {"/addresses/{id}/{path}", "/addresses/{id}"})
    public Object del(@PathVariable(value = "id", required = false) Integer id,
                      @PathVariable(value = "path", required = false) String path){
        JSONObject result = this.ipamAddressService.remove(id, path);
        if(result.getBoolean("success")){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
        }
    }
}
