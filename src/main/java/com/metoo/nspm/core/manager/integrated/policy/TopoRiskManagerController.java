package com.metoo.nspm.core.manager.integrated.policy;

import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoRiskDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/nspm/risk")
@RestController
public class TopoRiskManagerController {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;

    @ApiOperation("策略风险")
    @PostMapping(value = "alarm/access/newestRecordAndDistinguish")
    public Object newestRecordAndDistinguish(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/access/newestRecordAndDistinguish";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("访问关系（矩阵）")
    @PostMapping(value = "alarm/access/resultToMatrix")
    public Object resultToMatrix(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/access/resultToMatrix";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("访问关系（列表）")
    @PostMapping(value = "alarm/access/resultToList")
    public Object resultToList(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/access/resultToList";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("访问关系-规则列表")
    @PostMapping(value = "api/alarm/access/listAccessAlarm")
    public Object listAccessAlarm(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/access/listAccessAlarm";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("访问关系-立即检查")
    @PostMapping(value = "/api/alarm/access/check")
    public Object check(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/access/check";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("访问关系-立即检查进度")
    @PostMapping(value = "/api/alarm/access/percentage")
    public Object percentage(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/access/percentage";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("访问关系-停止检查")
    @PostMapping(value = "/api/danger/threadPool/shutdown")
    public Object shutdown(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/danger/threadPool/shutdown";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("访问关系-全局规则")
    @PostMapping(value = "/api/alarm/access/ruleAllList")
    public Object ruleAllList(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/access/ruleAllList";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("访问关系-新建规则")
    @PostMapping(value = "/api/alarm/access/insertOrUpdate")
    public Object insertOrUpdate(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/access/insertOrUpdate";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("访问关系-规则删除")
    @PostMapping(value = "/api/alarm/access/delete")
    public Object delete(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/access/delete";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("访问关系-预合规检查")
    @PostMapping(value = "/api/alarm/access/beforeCheck")
    public Object beforeCheck(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/access/beforeCheck";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间风险")
        @PostMapping(value = "/api/alarm/rule/newestRecord")
    public Object newestRecord(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/rule/newestRecord";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间风险-矩阵")
    @PostMapping(value = "/api/alarm/rule/getZoneAccessRuleAlarmToMatrix")
    public Object getZoneAccessRuleAlarmToMatrix(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/rule/getZoneAccessRuleAlarmToMatrix";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间风险-进度")
    @PostMapping(value = "/api/alarm/rule/percentage")
    public Object rulePercentage(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/rule/percentage";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间风险-列表")
    @PostMapping(value = "/api/alarm/rule/getZoneAccessRuleAlarmToList")
    public Object getZoneAccessRuleAlarmToList(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/rule/getZoneAccessRuleAlarmToList";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间风险-立即检查")
    @PostMapping(value = "/api/alarm/rule/check")
    public Object ruleChech(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/rule/check";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间风险-告警详情")
    @PostMapping(value = "/api/alarm/rule/listRuleAlarmDetail")
    public Object listRuleAlarmDetail(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/alarm/rule/listRuleAlarmDetail";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-地址对象")
    @PostMapping(value = "/api/compliance/get/object")
    public Object getObject(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/get/object";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-地址对象")
    @PostMapping(value = "/api/compliance/save/object")
    public Object saveObject(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/save/object";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-地址删除")
    @PostMapping(value = "/api/compliance/delete/object")
    public Object deleteObject(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/delete/object";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("目的地址/服务对象")
    @PostMapping(value = "/api/compliance/object/info")
    public Object info(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/object/info";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-规则矩阵")
    @PostMapping(value = "/api/compliance/matrix/list")
    public Object matrixList(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/matrix/list";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-规则矩阵-保存")
    @PostMapping(value = "/api/compliance/matrix/save")
    public Object matrixSave(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/matrix/save";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-规则矩阵-删除")
    @PostMapping(value = "/api/compliance/matrix/delete")
    public Object matrixDelete(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/matrix/delete";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-全局规则")
    @PostMapping(value = "/api/compliance/rules/list")
    public Object ruleList(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/rules/list";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-规则矩阵-新建")
    @PostMapping(value = "/api/compliance/get/menu")
    public Object getMenu(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/get/menu";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-全局规则-保存")
    @PostMapping(value = "/api/compliance/rules/save")
    public Object rulesSave(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/rules/save";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-全局规则-保存")
    @PostMapping(value = "/api/compliance/rules/update")
    public Object rulesUpdate(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/rules/update";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-全局规则-保存")
    @PostMapping(value = "/api/compliance/rules/delete")
    public Object rulesDelete(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/rules/delete";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域间合规-全局规则-保存")
    @PostMapping(value = "/api/compliance/verify/dredge")
    public Object verify(@RequestBody(required = false) TopoRiskDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "risk/api/compliance/verify/dredge";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }


}
