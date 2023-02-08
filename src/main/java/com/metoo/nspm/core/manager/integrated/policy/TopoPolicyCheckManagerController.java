package com.metoo.nspm.core.manager.integrated.policy;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.CheckDto;
import com.metoo.nspm.dto.TopoPolicyDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.beanutils.BeanMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RequestMapping("/nspm/patrol")
@RestController
public class TopoPolicyCheckManagerController {

    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private ISysConfigService sysConfigService;

    @ApiOperation("检查是设备和正在执行的任务")
    @PostMapping(value = "/check/overview/node/isExist")
    public Object isExist(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/patrol/api/check/overview/node/isExist";
            Object object = this.nodeUtil.postFormDataBody(null, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code") != null){
                if(!result.get("code").toString().equals("0")){
                    return ResponseUtil.error(result.get("msg").toString());
                }
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("获取检查最新记录")
    @PostMapping(value = "/check/newestRecord")
    public Object ruleList(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/patrol/api/check/overview/newestRecord";
            Object object = this.nodeUtil.postFormDataBody(null, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code") != null){
                if(!result.get("code").toString().equals("0")){
                    return ResponseUtil.error(result.get("msg").toString());
                }
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("检查设备计数")
    @PostMapping(value = "/check/statistics/mark")
    public Object mark(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/patrol/api/check/statistics/mark";
            Object object = this.nodeUtil.postFormDataBody(null, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code") != null){
                if(!result.get("code").toString().equals("0")){
                    return ResponseUtil.error(result.get("msg").toString());
                }
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("查询结果统计小类数据")
    @PostMapping(value = "/check/ruleType/list")
    public Object ruleType(@RequestBody(required = false)CheckDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/patrol/api/check/statistics/ruleType/list";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code") != null){
                if(!result.get("code").toString().equals("0")){
                    return ResponseUtil.error(result.get("msg").toString());
                }
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("统计列表数据")
    @PostMapping(value = "/check/summary/list")
    public Object summary(@RequestBody(required = false)CheckDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/patrol/api/check/statistics/summary/list";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code") != null){
                if(!result.get("code").toString().equals("0")){
                    return ResponseUtil.error(result.get("msg").toString());
                }
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("风险规则检查")
    @PostMapping(value = "/check/overview/check")
    public Object check(@RequestBody(required = false)CheckDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/patrol/api/check/overview/check";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code") != null){
                if(!result.get("code").toString().equals("0")){
                    return ResponseUtil.error(result.get("msg").toString());
                }
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("风险规则检查进度条")
    @PostMapping(value = "/check/overview/percentage")
    public Object percentage(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/patrol/api/check/overview/percentage";
            Object object = this.nodeUtil.postFormDataBody(null, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code") != null){
                if(!result.get("code").toString().equals("0")){
                    return ResponseUtil.error(result.get("msg").toString());
                }
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("停止当前正在检查的线程")
    @PostMapping(value = "/check/overview/stop/check")
    public Object stop(@RequestBody(required = false)CheckDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/patrol/api/check/overview/stop/check";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code") != null){
                if(!result.get("code").toString().equals("0")){
                    return ResponseUtil.error(result.get("msg").toString());
                }
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("下载策略优化Excel文件")
    @RequestMapping("/report/policyCheck/download")
    public Object policyCheck(HttpServletRequest request, String deviceUuid, String isReload){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/report/policyCheck/download";
            System.out.println(request.getMethod());
            TopoPolicyDto dto = new TopoPolicyDto();
            dto.setDeviceUuid(deviceUuid);
            dto.setIsReload(isReload);
            if(request.getMethod().equalsIgnoreCase("GET")){
                return this.nodeUtil.download(new BeanMap(dto), url, token);
            }else{
                Object object = this.nodeUtil.postFormDataBody(dto, url, token);
                return ResponseUtil.ok(object);
            }
        }
        return ResponseUtil.error();
    }
}
