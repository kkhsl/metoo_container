package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.Arp;

import java.util.List;
import java.util.Map;

public interface IArpHistoryService {

    Arp selectObjByIp(String ip);

    List<Arp> selectObjByMap(Map params);

    List<Arp> selectDistinctObjByMap(Map params);

    int batchDelete(List<Arp> arp);

    void copyArpTemp();
}
