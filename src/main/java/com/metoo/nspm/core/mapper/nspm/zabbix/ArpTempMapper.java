package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.ArpTemp;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface ArpTempMapper {

    List<ArpTemp> selectObjByDistinct();

    List<ArpTemp> selectOppositeByMap(Map params);

    List<ArpTemp> selectObjByInterface(Map params);

    List<ArpTemp> selectObjByGroupMap(Map params);

    List<ArpTemp> selectObjByGroupHavingInterfaceName(Map params);

    List<ArpTemp> selectObjByMac(Map params);

    List<ArpTemp> selectES(Map params);

    List<ArpTemp> selectEAndRemote(Map params);

    List<ArpTemp> selectSubquery(Map params);

    List<ArpTemp> selectObjByMap(Map params);

    List<ArpTemp> selectDistinctObjByMap(Map params);

    List<ArpTemp> arpTag(Map params);

    List<ArpTemp> selectGroupByHavingMac(Map params);

    ArpTemp selectObjByIp(String ip);

    int save(ArpTemp instance);

    int update(ArpTemp instance);

    void truncateTable();
}
