package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.dto.zabbix.RoutDTO;
import com.metoo.nspm.entity.nspm.Route;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface RouteHistoryMapper {

    Route selectObjById(Long id);

    List<Route> selectObjByMap(Map params);

    List<Route> selectConditionQuery(RoutDTO instance);

    Route selectDestDevice(Map params);

    int batchDelete(List<Route> macs);

    void copyRoutTemp();

}
