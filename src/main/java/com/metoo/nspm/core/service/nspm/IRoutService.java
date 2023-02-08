package com.metoo.nspm.core.service.nspm;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.zabbix.RoutDTO;
import com.metoo.nspm.entity.nspm.Route;

import java.util.List;
import java.util.Map;

public interface IRoutService {

    Route selectObjById(Long id);
    Page<Route> selectConditionQuery(RoutDTO instance);
    List<Route> selectObjByMap(Map params);
    int save(Route instance);
    int update(Route instance);
    int delete(Long id);
    void truncateTable();
    List<Route> queryDestDevice(Map params);

    Route selectDestDevice(Map params);

    List<Route> selectNextHopDevice(Map params);

    void copyRoutTemp();
}
