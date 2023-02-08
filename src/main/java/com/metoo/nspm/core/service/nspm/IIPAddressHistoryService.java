package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.IpAddress;

import java.util.List;
import java.util.Map;

public interface IIPAddressHistoryService {

    List<IpAddress> selectObjByMap(Map map);

    IpAddress selectObjByMac(String mac);

    IpAddress selectObjByIp(String ip);

    IpAddress querySrcDevice(Map params);

    int batchDelete(List<IpAddress> ipAddresses);

    void copyIpAddressTemp();

}
