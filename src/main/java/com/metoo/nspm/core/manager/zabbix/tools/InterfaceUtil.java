package com.metoo.nspm.core.manager.zabbix.tools;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.zabbix.InterfaceService;
import com.metoo.nspm.entity.zabbix.Interface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class InterfaceUtil {

    @Autowired
    private InterfaceService interfaceService;

    public boolean verifyHostIsAvailable(String ip){
        Interface obj = this.interfaceService.selectObjByIp(ip);
        if(obj != null && obj.getAvailable() != null){
            if(obj.getAvailable().equals("1")){
                return true;
            }
        }
        return false;
    }
    public String getInterfaceAvaliable(String ip){
        Interface obj = this.interfaceService.selectObjByIp(ip);
        if(obj != null && obj.getAvailable() != null){
            return obj.getAvailable();
        }
        return "-1";
    }
}
