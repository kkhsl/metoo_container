package com.metoo.nspm.core.manager.ipam;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.phpipam.IpamVlanService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.Ipam.IpamVlan;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@Api("VLAN")
@RequestMapping("/ipam")
@RestController
public class IpamVlanManagerController {

    @Autowired
    private IpamVlanService ipamVlanService;

    @ApiOperation("虚拟局域网")
    @RequestMapping(value = {"/vlan/{id}", "/vlan"})
    public Object vlan(@PathVariable(required = false) Integer id){
        return ResponseUtil.ok(this.ipamVlanService.vlan(id));
    }

    @ApiOperation("vlan")
    @PostMapping(value = {"/vlan"})
    public Object create(@RequestBody(required = false) IpamVlan instance){
        JSONObject result = this.ipamVlanService.create(instance);
        if(result != null){
            if(result.getBoolean("success")){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
            }
        }
        return ResponseUtil.error();
    }


    @ApiOperation("vlan")
    @PatchMapping(value = {"/vlan"})
    public Object update(@RequestBody(required = false) IpamVlan instance){
        JSONObject result = this.ipamVlanService.update(instance);
        if(result != null){
            if(result.getBoolean("success")){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
            }
        }
        return ResponseUtil.error();
    }

    @ApiOperation("vlan删除")
    @DeleteMapping(value = {"/vlan/{id}/{path}", "/vlan/{id}"})
    public Object del(@PathVariable(value = "id", required = false) Integer id,
                      @PathVariable(value = "path", required = false) String path){
        JSONObject result = this.ipamVlanService.remove(id, path);
        if(result.getBoolean("success")){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.badArgument(result.getInteger("code"), result.getString("message"));
        }
    }


}
