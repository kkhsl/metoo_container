package com.metoo.nspm.core.manager.ipam;


import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.phpipam.IpamL2DomainService;
import com.metoo.nspm.core.service.phpipam.IpamVlanService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.Ipam.IpamDomain;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RequestMapping("/ipam")
@RestController
public class IpamVlamDomaininManagerController {

    @Autowired
    private IpamL2DomainService ipamL2DomainService;
    @Autowired
    private IpamVlanService ipamVlanService;

    @ApiOperation("L2域")
    @GetMapping(value = {"/l2domain/{id}", "/l2domain"})
    public Object l2domain(@PathVariable(required = false) Integer id){
        JSONObject result = this.ipamL2DomainService.l2domains(id);
        if(result != null && result.getBoolean("success")){
            // 递归获取数据等级
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
    }

    @ApiOperation("所有域中的所有VLAN的列表")
    @GetMapping(value = {"/l2domains/{id}/vlans"})
    public Object vlans(@PathVariable(required = false) Integer id){
        JSONObject result = this.ipamL2DomainService.vlans(id);
        if(result != null && result.getBoolean("success")){
            Object data = result.get("data");
            if(data instanceof JSONObject){
                return ResponseUtil.ok(result);
            }
            if(data instanceof JSONArray){
                JSONArray array = JSONArray.parseArray(data.toString());
                List list = new ArrayList();
                for (Object obj : array){
                    JSONObject ele = JSONObject.parseObject(obj.toString());
                    Object object = this.ipamVlanService.vlanSubnets(ele.getInteger("vlanId"));
                    if(object != null){
                        JSONArray subnets = JSONArray.parseArray(object.toString());
                        JSONObject subnet = JSONObject.parseObject(JSON.toJSONString(subnets.get(0)));
                        ele.put("subnet", subnet.getString("subnet"));
                        ele.put("mask", subnet.getString("mask"));
                    }
                    list.add(ele);
                }
                return ResponseUtil.ok(list);
            }
        }
        return ResponseUtil.ok();
    }

    @ApiOperation("domain")
    @PostMapping(value = {"/l2domain"})
    public Object create(@RequestBody IpamDomain instance){
        JSONObject result = this.ipamL2DomainService.create(instance);
        if(result != null){
            if(result.getBoolean("success")){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
            }
        }
        return ResponseUtil.error();
    }

    @ApiOperation("domain")
    @PatchMapping(value = {"/l2domain"})
    public Object update(@RequestBody IpamDomain instance){
        JSONObject result = this.ipamL2DomainService.update(instance);
        if(result != null){
            if(result.getBoolean("success")){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
            }
        }
        return ResponseUtil.error();
    }

    @ApiOperation("L2Domain删除")
    @DeleteMapping(value = {"/l2domain/{id}/{path}", "/l2domain/{id}"})
    public Object del(@PathVariable(value = "id", required = false) Integer id,
                      @PathVariable(value = "path", required = false) String path){
        JSONObject result = this.ipamL2DomainService.remove(id, path);
        if(result.getBoolean("success")){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
        }
    }

}
