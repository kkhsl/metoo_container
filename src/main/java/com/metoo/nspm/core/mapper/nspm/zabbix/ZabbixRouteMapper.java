package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.dto.zabbix.RoutDTO;
import com.metoo.nspm.entity.nspm.Route;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface ZabbixRouteMapper {

    Route selectObjById(Long id);
    List<Route> selectConditionQuery(RoutDTO instance);
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
