package com.metoo.nspm.core.manager.integrated.node;

import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoZoneDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Api("域管理")
@RequestMapping("/nspm/risk/api")
@RestController
public class TopoZoneManagerAction {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;

    @ApiOperation("安全域")
    @RequestMapping("/alarm/zone/listLogicZone")
    public Object listLogicZone(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/listLogicZone";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("业务域")
    @RequestMapping("/danger/businessZone/pageList")
    public Object pageList(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/businessZone/pageList";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("业务域节点")
    @RequestMapping("/danger/businessZone/businessZoneTree")
    public Object businessZoneTree(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/businessZone/businessZoneTree";
            Object result = this.nodeUtil.postFormSend(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("编辑业务域")
    @RequestMapping("/danger/businessZone/getByBusinessZoneUuid")
    public Object getByBusinessZoneUuid(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/businessZone/getByBusinessZoneUuid";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }


    @ApiOperation("编辑业务域(名称)")
    @RequestMapping("/danger/businessZone/businessZoneRename")
    public Object businessZoneRename(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/businessZone/businessZoneRename";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }


    @ApiOperation("可选逻辑域")
    @RequestMapping("/danger/businessZone/getOptionalLogicZoneList")
    public Object getOptionalLogicZoneList(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/businessZone/getOptionalLogicZoneList";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("删除逻辑域")
    @RequestMapping("/alarm/zone/deleteLogicZone")
    public Object deleteLogicZone(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/deleteLogicZone";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("新建业务域")
    @RequestMapping("/danger/businessZone/addOrEdit")
    public Object addOrEdit(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/businessZone/addOrEdit";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("删除业务域")
    @RequestMapping("/danger/businessZone/deleteByUuid")
    public Object deleteByUuid(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/businessZone/deleteByUuid";
            Object result = this.nodeUtil.postFormSend(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("批量移动")
    @RequestMapping("/danger/businessZone/bulkMove")
    public Object bulkMove(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/businessZone/bulkMove";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("所含子网")
    @RequestMapping("/alarm/zone/listLogicZoneSubnet")
    public Object listLogicZoneSubnet(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/listLogicZoneSubnet";
            Object result = this.nodeUtil.postFormSend(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域分类")
    @RequestMapping("/alarm/zone/listZoneType")
    public Object listZoneType(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/listZoneType";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("域细分类型")
    @RequestMapping("/alarm/zone/listZoneTypeDetail")
    public Object listZoneTypeDetail(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/listZoneTypeDetail";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("子网")
    @RequestMapping("/alarm/zone/listDeviceSubnet")
    public Object listDeviceSubnet(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/listDeviceSubnet";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("新建安全域")
    @RequestMapping("/alarm/zone/saveOrUpdateLogicZone")
    public Object saveOrUpdateLogicZone(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/saveOrUpdateLogicZone";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("编辑安全域")
    @RequestMapping("/alarm/zone/getByZoneUuid")
    public Object getByZoneUuid(@RequestBody(required = false) TopoZoneDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/getByZoneUuid";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }


}
