package com.metoo.nspm.core.manager.myzabbix.zabbixapi;

import com.metoo.nspm.core.service.api.zabbix.ZabbixHostInterfaceService;
import com.metoo.nspm.core.utils.ResponseUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/zabbix/host")
@RestController
public class ZabbixHostInterfaceManagerController {

    @Autowired
    private ZabbixHostInterfaceService zabbixHostInterfaceService;

    @RequestMapping("/host/interface")
    public Object hostInterface(String ip){
        return this.zabbixHostInterfaceService.getHostInterfaceByIp(ip);
    }

    @GetMapping("/{ip}")
    public Object available(@PathVariable(value = "ip") String ip){
        String avaliable = this.zabbixHostInterfaceService.getInterfaceAvaliable(ip);
        return ResponseUtil.ok(avaliable);
    }
}
