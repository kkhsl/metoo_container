package com.metoo.nspm.core.service.nspm;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.MacDTO;
import com.metoo.nspm.entity.nspm.Mac;

import java.util.List;
import java.util.Map;

public interface IMacService {

    Page<Mac> selectObjConditionQuery(MacDTO dto);

    List<Mac> selectByMap(Map params);

    Mac getObjByInterfaceName(String interfaceName);

    List<Mac> groupByObjByMap(Map params);

    List<Mac> groupByObjByMap2(Map params);

    List<Mac> getMacUS(Map params);

    List<Mac> macJoinArp(Map params);

    Mac selectByMac(String mac);

    int save(Mac instance);

    int update(Mac instance);

    void truncateTable();

    void copyMacTemp();
}
