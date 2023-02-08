package com.metoo.nspm.core.manager.integrated.policy;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoPolicyDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.beanutils.BeanMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@Api("策略列表-策略相关")
@RequestMapping("/nspm/policy")
@RestController
public class TopoPolocyListManagerController {


    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private IUserService userService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IPolicyService policyService;
    @Autowired
    private IPolicyStatisticalService policyStatisticalService;
    @Autowired
    private IssuedService ssuedService;

    @ApiOperation("策略列表统计")
    @PostMapping(value = "/policy-list-pie")
    public Object policyListPie(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/report/policy/policy-list-pie";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("根据策略集uuid查询策略规则")
    @PostMapping(value = "/rule-list-search")
    public Object ruleListSearch(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/rule-list-search";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(object);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("下载策略列表Excel文件")
    @RequestMapping("/report/policyList/download")
    public Object policyListDownLoad(HttpServletRequest request, String deviceUuid, String isReload){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/report/policyList/download";
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

    public JSONObject parseObject(Object object){
        if (object != null)
            return JSONObject.parseObject(object.toString());
        return null;
    }
}
