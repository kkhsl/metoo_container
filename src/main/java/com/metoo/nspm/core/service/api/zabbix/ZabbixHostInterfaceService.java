package com.metoo.nspm.core.service.api.zabbix;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.dto.zabbix.HostInterfaceDTO;

public interface ZabbixHostInterfaceService {


    JSONObject getHostInterface(HostInterfaceDTO dto);

    JSONObject getHostInterfaceByIp(String ip);

    String getHostInterfaceIdByHostId(String hostid);

    public String getInterfaceAvaliable(String ip);

    public JSONObject getHostInterfaceInfo(String ip);

    public JSONObject update(HostInterfaceDTO dto);

}
