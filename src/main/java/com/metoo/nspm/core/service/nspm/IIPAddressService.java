package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.IpAddress;

import java.util.List;
import java.util.Map;

public interface IIPAddressService {

    List<IpAddress> selectObjByMap(Map map);

    IpAddress selectObjByMac(String mac);

    IpAddress selectObjByIp(String ip);

    int save(IpAddress instance);

    int update(IpAddress instance);

    void truncateTable();

    void copyIpAddressTemp();

    IpAddress querySrcDevice(Map params);
}
