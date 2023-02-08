package com.metoo.nspm.core.service.nspm;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.ArpDTO;
import com.metoo.nspm.entity.nspm.Arp;

import java.util.List;
import java.util.Map;

public interface IArpService {

    List<Arp> selectObjByDistinct();

    List<Arp> selectOppositeByMap(Map params);

    List<Arp> selectObjByInterface(Map params);

    List<Arp> selectObjByMac(Map params);

    List<Arp> selectES(Map params);

    List<Arp> selectEAndRemote(Map params);

    List<Arp> selectObjByGroupMap(Map params);

    List<Arp> selectObjByGroupHavingInterfaceName(Map params);

    Page<Arp> selectObjConditionQuery(ArpDTO dto);

    List<Arp> selectObjByMap(Map params);

    List<Arp> selectDistinctObjByMap(Map params);

    List<Arp> arpTag(Map map);

    List<Arp> selectSubquery(Map map);

    List<Arp> selectGroupByHavingMac(Map map);

    Arp selectObjByIp(String ip);

    int save(Arp instance);

    int update(Arp instance);

    void truncateTable();

    void copyArpTemp();

    List<Arp> selectObjByMutual();
}
