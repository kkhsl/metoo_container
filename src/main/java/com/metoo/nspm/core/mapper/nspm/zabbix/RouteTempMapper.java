package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.RouteTemp;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface RouteTempMapper {

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
