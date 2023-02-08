package com.metoo.nspm.core.manager.integrated.sysconfig;

import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoSysconfigDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/nspm/topology-monitor")
@RestController
public class SystemConfigManager {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;

    @ApiOperation("磁盘配置")
    @RequestMapping("/system/xxlCh/GET/xxlChConfig")
    public Object getxxlChConfig(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-monitor/system/xxlCh/GET/xxlChConfig";
            Object result = this.nodeUtil.postBody(null, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("阈值设置")
    @RequestMapping("/system/xxlCh/POST/xxlChConfig")
    public Object postxxlChConfig(@RequestBody(required = false)TopoSysconfigDto topoSysconfigDto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-monitor/system/xxlCh/POST/xxlChConfig";
            Object result = this.nodeUtil.postFormDataBody(topoSysconfigDto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }



    @ApiOperation("ip地址")
    @RequestMapping("/monitor/deviceLog/GET/ipAddresses")
    public Object ipAddresses(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-monitor/monitor/deviceLog/GET/ipAddresses";
            Object result = this.nodeUtil.getBody(null, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }
    @ApiOperation("各类型日志磁盘占比(KB)")
    @GetMapping("/monitor/deviceLog/GET/logDisk")
    public Object logDisk(TopoSysconfigDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-monitor/monitor/deviceLog/GET/logDisk";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("各类型日志接收趋势图(最近一天,条/s)")
    @GetMapping("/monitor/server/GET/listServerStatus")
    public Object listServerStatus(TopoSysconfigDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-monitor/monitor/server/GET/listServerStatus";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("各类型日志总量统计(条)")
    @GetMapping("/monitor/deviceLog/GET/logTotalCount")
    public Object logTotalCount(TopoSysconfigDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-monitor/monitor/deviceLog/GET/logTotalCount";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("CPU、MEM、DISK 趋势图(最近一天,%)")
    @GetMapping("/monitor/deviceLog/GET/logCountList")
    public Object logCountList(TopoSysconfigDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-monitor/monitor/deviceLog/GET/logCountList";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

}
