package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.ArpTemp;

import java.util.List;
import java.util.Map;

public interface IArpTempService {

    List<ArpTemp> selectObjByDistinct();

    List<ArpTemp> selectOppositeByMap(Map params);

    List<ArpTemp> selectObjByInterface(Map params);

    List<ArpTemp> selectObjByMac(Map params);

    List<ArpTemp> selectES(Map params);

    List<ArpTemp> selectEAndRemote(Map params);

    List<ArpTemp> selectObjByGroupMap(Map params);

    List<ArpTemp> selectObjByGroupHavingInterfaceName(Map params);

    List<ArpTemp> selectObjByMap(Map params);

    List<ArpTemp> selectDistinctObjByMap(Map params);

    List<ArpTemp> arpTag(Map map);

    List<ArpTemp> selectSubquery(Map map);

    List<ArpTemp> selectGroupByHavingMac(Map map);

    ArpTemp selectObjByIp(String ip);

    int save(ArpTemp instance);

    int update(ArpTemp instance);

    void truncateTable();

}
