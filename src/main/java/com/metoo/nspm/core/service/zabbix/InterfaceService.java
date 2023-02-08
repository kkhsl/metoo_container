package com.metoo.nspm.core.service.zabbix;

import com.metoo.nspm.entity.zabbix.Interface;

public interface InterfaceService {

    Interface selectObjByIp(String ip);
}
