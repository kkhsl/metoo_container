package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.Mac;

import java.util.List;
import java.util.Map;

public interface IMacHistoryService {

    List<Mac> selectObjByMap(Map params);

    int batchDelete(List<Mac> macs);

    void copyMacTemp();
}
