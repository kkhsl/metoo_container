package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.RouteTable;

import java.util.List;
import java.util.Map;

public interface IRoutTableService {

    List<RouteTable> selectObjByMap(Map params);

    RouteTable selectObjByMac(String mac);

    RouteTable selectObjByIp(String ip);

    int save(RouteTable instance);

    int update(RouteTable instance);

    void truncateTable();
}
