package com.metoo.nspm.core.manager.zabbix.action;

import com.metoo.nspm.core.service.zabbix.InterfaceService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.zabbix.Interface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/admin/interface")
@RestController
public class InterfaceManagerControler {

    @Autowired
    private InterfaceService interfaceService;

    @GetMapping
    public Object getInterface(@RequestParam String ip){
        Interface obj = this.interfaceService.selectObjByIp(ip);
        return ResponseUtil.ok(obj);
    }
}
