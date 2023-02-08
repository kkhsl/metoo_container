package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.Address;

import java.util.List;
import java.util.Map;

public interface IAddressService {

    Address selectObjById(Long id);

    Address selectObjByIp(String ip);

    Address selectObjByMac(String mac);

    List<Address> selectObjByMap(Map map);

    int save(Address instance);

    int update(Address instance);

    int delete(Long id);

    void truncateTable();

}
