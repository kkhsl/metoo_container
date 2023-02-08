package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.RouteTemp;

import java.util.List;
import java.util.Map;

public interface IRoutTempService {

    RouteTemp selectObjById(Long id);

    List<RouteTemp> selectObjByMap(Map params);

    int save(RouteTemp instance);

    int update(RouteTemp instance);

    int delete(Long id);

    void truncateTable();

    List<RouteTemp> queryDestDevice(Map params);

    RouteTemp selectDestDevice(Map params);

    List<RouteTemp> selectNextHopDevice(Map params);
}
