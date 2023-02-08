package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.IDeviceTypeService;
import com.metoo.nspm.core.service.nspm.IIndexService;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.service.nspm.IssuedService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.DeviceType;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.entity.nspm.Task;
import com.metoo.nspm.entity.nspm.User;
import com.metoo.nspm.vo.DeviceTypeVO;
import com.metoo.nspm.vo.MenuVo;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("系统首页")
@RequestMapping("/index")
@RestController
public class IndexManageController {

    @Autowired
    private IIndexService indexService;
    @Autowired
    private ISysConfigService configService;
    @Autowired
    private IssuedService issuedService;
    @Autowired
    private IDeviceTypeService deviceTypeService;

//    @RequiresPerions("ADMIN:INDEX:MENU")
    @ApiOperation("系统菜单")
    @RequestMapping("/menu")
    public Object menu(){
        Map map = new HashMap();
        User user = ShiroUserHolder.currentUser();
        List<MenuVo> menuList = this.indexService.findMenu(user.getId());
        map.put("obj", menuList);
        map.put("userRole", user.getUserRole());
        SysConfig configs = this.configService.select();
        map.put("domain", configs.getDomain());
        return ResponseUtil.ok(map);
    }

    @ApiOperation("系统导航")
    @RequestMapping("/nav")
    public Object nav(){
        Map map = new HashMap();
        User user = ShiroUserHolder.currentUser();
        List<MenuVo> menuList = this.indexService.findMenu(user.getId());
        map.put("obj", menuList);
        SysConfig configs = this.configService.select();
        map.put("domain", configs.getDomain());
        return ResponseUtil.ok(map);
    }

    // 策略统计
    // 对象统计
    // 工单统计
    // 网元统计
    @RequestMapping("/task")
    public Object task(){
        List<Task> taskList = this.issuedService.query();
        return ResponseUtil.ok(taskList);
    }

    @RequestMapping("/device")
    public Object device(){
        List<DeviceType> deviceTypeList = this.deviceTypeService.selectCountByLeftJoin();
        return ResponseUtil.ok(deviceTypeList);
    }

    @RequestMapping("/statistics")
    public Object statistics(){
        List<DeviceTypeVO> deviceTypeList = this.deviceTypeService.statistics();
        return ResponseUtil.ok(deviceTypeList);
    }

}
