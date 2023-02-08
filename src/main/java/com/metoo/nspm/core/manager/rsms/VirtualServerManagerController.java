package com.metoo.nspm.core.manager.rsms;

import com.metoo.nspm.core.config.annotation.OperationLogAnno;
import com.metoo.nspm.core.config.annotation.OperationType;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.IOperationSystemService;
import com.metoo.nspm.core.service.nspm.IRsmsDeviceService;
import com.metoo.nspm.core.service.nspm.IVirtualServerService;
import com.metoo.nspm.core.service.nspm.IVirtualTypeService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.VirtualServerDto;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.vo.RsmsDeviceVo;
import com.github.pagehelper.Page;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("虚拟服务器")
@RequestMapping("/admin/rsms/virtual/server")
@RestController
public class VirtualServerManagerController {

    @Autowired
    private IVirtualServerService virtualServerService;
    @Autowired
    private IVirtualTypeService virtualTypeService;
    @Autowired
    private IOperationSystemService operationSystemService;
    @Autowired
    private IRsmsDeviceService rsmsDeviceService;

    @GetMapping("/add")
    public Object add(){
        User user = ShiroUserHolder.currentUser();
        // 设备
        Map map = new HashMap();
        map.put("rsms_device_type", 3);
        map.put("userId", user.getId());
        List<RsmsDeviceVo> deviceList = this.rsmsDeviceService.selectNameByMap(map);
        // 服务器类型
        List<VirtualType> virtualTypeList = this.virtualTypeService.selectByMap(null);
        // 操作系统
        List<OperationSystem> operationSystemList = this.operationSystemService.selectByMap(null);
        Map result = new HashMap();
        result.put("virtualTypeList", virtualTypeList);
        result.put("operationSystemList", operationSystemList);
        result.put("deviceList", deviceList);
        return ResponseUtil.ok(result);
    }

    @GetMapping("/update")
    public Object update(@RequestParam(value = "id") String id){
        VirtualServer virtualServer = this.virtualServerService.getObjById(Long.parseLong(id));
        if(virtualServer == null){
            return ResponseUtil.badArgument("参数错误");
        }
        // 设备
        Map map = new HashMap();
        map.put("rsms_device_type", 3);
        List<RsmsDeviceVo> deviceList = this.rsmsDeviceService.selectNameByMap(map);
        // 服务器类型
        List<VirtualType> virtualTypeList = this.virtualTypeService.selectByMap(null);
        // 操作系统
        List<OperationSystem> operationSystemList = this.operationSystemService.selectByMap(null);
        Map result = new HashMap();
        result.put("virtualTypeList", virtualTypeList);
        result.put("operationSystemList", operationSystemList);
        result.put("deviceList", deviceList);
        result.put("virtualServer", virtualServer);
        return ResponseUtil.ok(result);
    }

    @GetMapping("/detail")
    public Object detail(@RequestParam(value = "id") String id){
        VirtualServer virtualServer = this.virtualServerService.getObjById(Long.parseLong(id));
        if(virtualServer == null){
            return ResponseUtil.badArgument("参数错误");
        }
        return ResponseUtil.ok(virtualServer);
    }

    @PostMapping("/list")
    public Object list(@RequestBody VirtualServerDto dto){
        Page<VirtualServer> page = this.virtualServerService.selectList(dto);
        if(page.size() > 0){
            return ResponseUtil.ok(new PageInfo<Rack>(page));
        }
        return ResponseUtil.ok();
    }

    @OperationLogAnno(operationType= OperationType.CREATE, name = "virtualServer")
    @PostMapping("/save")
    public Object save(@RequestBody VirtualServer instance){
        if(instance == null){
            return ResponseUtil.badArgument();
        }
        int flag = this.virtualServerService.insert(instance);
        if(flag > 0){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error();
    }

    @ApiOperation("删除虚拟服务器")
    @DeleteMapping("/del")
    public Object del(@RequestParam(value = "id") String id){
        VirtualServer instance = this.virtualServerService.getObjById(Long.parseLong(id));
        if(instance == null){
            return ResponseUtil.badArgument("资源不存在");
        }
        int flag = this.virtualServerService.deleteById(Long.parseLong(id));
        if (flag != 0){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error("删除失败");
    }

    @ApiOperation("虚拟服务器批量删除")
    @DeleteMapping("/batch/del")
    public Object batchDel(@RequestParam(value = "ids") String ids){
        String[] l = ids.split(",");
        List<String> list = Arrays.asList(l);
        for (String id : list){
            VirtualServer instance = this.virtualServerService.getObjById(Long.parseLong(id));
            if(instance == null){
                return ResponseUtil.badArgument("id：" + id + "资源不存在");
            }
        }
        Map map  = new HashMap();
        map.put("ids", ids);
        int flag = this.virtualServerService.deleteByMap(map);
        if (flag != 0){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error("删除失败");
    }
}
