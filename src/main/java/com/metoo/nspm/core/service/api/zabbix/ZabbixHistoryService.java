package com.metoo.nspm.core.service.api.zabbix;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.dto.zabbix.HistoryDTO;

public interface ZabbixHistoryService {

    JSONObject getHistory(HistoryDTO dto);
}
