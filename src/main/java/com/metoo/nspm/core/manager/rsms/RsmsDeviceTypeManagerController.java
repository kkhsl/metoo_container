package com.metoo.nspm.core.manager.rsms;

import com.metoo.nspm.core.service.nspm.IDeviceTypeService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.DeviceType;
import io.swagger.annotations.Api;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Api("设备类型")
@RequestMapping("/admin/device/type")
@RestController
public class RsmsDeviceTypeManagerController {

    @Autowired
    private IDeviceTypeService deviceTypeService;


    @GetMapping("/count")
    public Object getCount(){
        List<DeviceType> deviceTypes = this.deviceTypeService.selectDeviceTypeAndNeByJoin();
        return ResponseUtil.ok(deviceTypes);
    }
}
