package com.metoo.nspm.core.manager.integrated.node;

import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoNodeDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

//@RequiresPermissions("ADMIN:SUBNET:MANAGER")
@Api("子网列表")
@RequestMapping("/nspm/subnet")
@RestController
public class TopoSubnetManagerController {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private NodeUtil nodeUtil;

    @ApiOperation("列表")
    @RequestMapping("/topology/whaleSubnet/GET/subnets")
    public Object subnets(@RequestBody(required = false) TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/whaleSubnet/GET/subnets";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("批量编辑")
    @RequestMapping("/topology/whaleSubnet/PUT/subnets/batch-update-level")
    public Object batchUpdateLevel(@RequestBody(required = false) TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/whaleSubnet/PUT/subnets/batch-update-level";
            Object result = this.nodeUtil.putBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("批量编辑")
    @RequestMapping("/topology/whaleSubnet/PUT/subnet")
    public Object subnet(@RequestBody(required = false) TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/whaleSubnet/PUT/subnet";
            Object result = this.nodeUtil.putBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("起点标签")
    @RequestMapping("/push/recommend/label/list")
    public Object labelList(@RequestBody(required = false) TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/label/list";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("子网Excel下载")
    @GetMapping("/topology/whaleSubnet/GET/subnet/excel")
    public Object download(){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/whaleSubnet/GET/subnet/excel";
            Map map = new HashMap();
            map.put("page", 1);
            map.put("size", 10000);
            return this.nodeUtil.downloadPost(map, url, token);
        }
        return ResponseUtil.error();
    }
}
