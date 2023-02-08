package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.LocalIpAddress;

import java.util.List;
import java.util.Map;

public interface ILocalIpAddressService {

    List<LocalIpAddress> selectObjByMap(Map map);

    int save(LocalIpAddress instance);

    void truncateTable();
}
