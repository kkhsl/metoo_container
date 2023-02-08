package com.metoo.nspm.core.service.nspm;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.zabbix.RoutDTO;
import com.metoo.nspm.entity.nspm.Route;

import java.util.List;
import java.util.Map;

public interface IRoutHistoryService {

    Route selectObjById(Long id);

    List<Route> selectObjByMap(Map params);

    Page<Route> selectConditionQuery(RoutDTO instance);

    Route selectDestDevice(Map params);

    int batchDelete(List<Route> routs);

    void copyRoutTemp();
}
