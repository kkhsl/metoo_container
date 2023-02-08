package com.metoo.nspm.core.service.topo;

import java.util.List;
import java.util.Map;

public interface ITopoNodeService {

    // 获取所有网元
    List<Map> queryAnt();

    // 获取所有网元

    /**
     * 获取所有可用网元
     * @return
     */
    List<Map> queryNetworkElement();
}
