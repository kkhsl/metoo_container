package com.metoo.nspm.core.manager.integrated.node;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoCycleDto;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;

//@RequiresPermissions("ADMIN:CYCLE:MANAGER")
@Api("采集周期")
@RequestMapping("/nspm/cycle")
@RestController
public class TopoCycleManagerController {
    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private NodeUtil nodeUtil;

    public static void main(String[] args) {
        long n = 1667388659 / 60;
        System.out.println(n);
        long m = 1667388659 / 60;
        double diff = (1667388778 - 1667388659);
        System.out.println(diff / 60);
        double diffMinutes = Math.round(diff / 60);
        System.out.println(diffMinutes);


    }

    @ApiOperation("列表")
    @RequestMapping("/topology/cycle/getCyclePage")
    public Object getCyclePage(@RequestBody(required = false) TopoCycleDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/cycle/getCyclePage";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            JSONArray arrays = JSONArray.parseArray(result.get("data").toString());
            List list = new ArrayList();
            for (Object array : arrays) {
                JSONObject data = JSONObject.parseObject(array.toString());
                if (data.get("branchLevel") != null) {
                    Group group = this.groupService.getObjByLevel(data.get("branchLevel").toString());
                    if (group != null) {
                        data.put("branchName", group.getBranchName());
                        list.add(data);
                    }
                }
            }
            result.put("data", list);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("新增")
    @RequestMapping("/topology/cycle/saveCycle")
    public Object saveCycle(TopoCycleDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/cycle/saveCycle";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("编辑")
    @RequestMapping("/topology/cycle/updateCycle")
    public Object updateCycle(TopoCycleDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/cycle/updateCycle";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("分配组")
    @RequestMapping("/topology/cycle/batch-cycle-update")
    public Object batchUpdate(@RequestBody(required = false) TopoCycleDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/cycle/batch-cycle-update";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("删除")
    @PostMapping("/topology/cycle/deleteCycle")
    public Object deleteCycle(@RequestBody(required = false) TopoCycleDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/cycle/deleteCycle";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

}
