package com.metoo.nspm.core.manager.myzabbix.zabbixapi;

import com.metoo.nspm.core.service.nspm.IRoutService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.Route;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/zabbix/item/rout")
@RestController
public class ZabbixRoutManagerController {

    @Autowired
    private IRoutService zabbixRoutService;

    @RequestMapping(value = {"{id}"})
    public Object rout(@PathVariable(name = "id") Long id){
        return ResponseUtil.ok(this.zabbixRoutService.selectObjById(id));
    }

    @PostMapping
    public Object save(@RequestBody Route instance){
        return ResponseUtil.ok(this.zabbixRoutService.save(instance));
    }
}
