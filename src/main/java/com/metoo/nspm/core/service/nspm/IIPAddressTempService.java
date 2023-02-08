package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.IpAddressTemp;

import java.util.List;
import java.util.Map;

public interface IIPAddressTempService {

    List<IpAddressTemp> selectObjByMap(Map map);

    IpAddressTemp selectObjByMac(String mac);

    IpAddressTemp selectObjByIp(String ip);

    int save(IpAddressTemp instance);

    int update(IpAddressTemp instance);

    void truncateTable();

    IpAddressTemp querySrcDevice(Map params);
}
