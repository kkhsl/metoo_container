package com.metoo.nspm.core.service.api.zabbix;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.dto.zabbix.HostDTO;

public interface ZabbixHostService {

    JSONObject getHost(HostDTO dto);

    String getHostId(String ip);

    boolean getHostMaintenanceStatus(String ip);

    boolean verifyHost(String ip);

    boolean deleteHost(String ip);

}
