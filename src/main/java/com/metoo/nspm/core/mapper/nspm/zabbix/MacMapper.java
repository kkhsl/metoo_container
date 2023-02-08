package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.MacDTO;
import com.metoo.nspm.entity.nspm.Mac;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface MacMapper {

    List<Mac> selectObjConditionQuery(MacDTO dto);

    Mac selectByMac(String mac);

    List<Mac> selectByMap(Map params);

    Mac getObjByInterfaceName(String interfaceName);

    List<Mac> getMacUS(Map params);

    List<Mac> selectObjByMap(Map params);

    List<Mac> groupByObjByMap(Map params);


    List<Mac> groupByObjByMap2(Map params);

    List<Mac> macJoinArp(Map params);

    int save(Mac instance);

    int update(Mac instance);

    void truncateTable();

    void copyMacTemp();
}
