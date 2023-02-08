package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.Topology;

import java.util.List;
import java.util.Map;

public interface ITopologyHistoryService {

    List<Topology> selectObjByMap(Map params);

}
