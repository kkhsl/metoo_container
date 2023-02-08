package com.metoo.nspm.core.manager.admin.action;

import com.github.pagehelper.Page;
import com.metoo.nspm.core.service.nspm.IArpService;
import com.metoo.nspm.core.service.nspm.IDeviceService;
import com.metoo.nspm.core.service.nspm.INetworkElementService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.ArpDTO;
import com.metoo.nspm.entity.nspm.Arp;
import com.metoo.nspm.entity.nspm.DeviceConfig;
import com.metoo.nspm.entity.nspm.NetworkElement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sun.nio.ch.Net;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequestMapping("/admin/arp")
@RestController
public class ArpManagerController {

    @Autowired
    private IArpService arpService;
    @Autowired
    private INetworkElementService networkElementService;

    @RequestMapping("/list")
    public Object deviceArp(@RequestBody(required = false) ArpDTO dto){
        NetworkElement networkElement = this.networkElementService.selectObjByUuid(dto.getUuid());
        if(networkElement != null){
            Map params = new HashMap();
            params.put("deviceUuid", networkElement.getUuid());
            Page<Arp> page = this.arpService.selectObjConditionQuery(dto);
            if(page.getResult().size() > 0){
                return ResponseUtil.ok(new PageInfo<Arp>(page));
            }
            return ResponseUtil.ok();
        }
        return ResponseUtil.badArgument("设备不存在");
    }

}
