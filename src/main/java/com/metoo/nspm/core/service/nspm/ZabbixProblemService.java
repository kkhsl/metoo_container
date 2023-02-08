package com.metoo.nspm.core.service.nspm;

import com.alibaba.fastjson.JSONArray;
import com.metoo.nspm.dto.zabbix.ProblemDTO;

public interface ZabbixProblemService {

    Object get(ProblemDTO dto);

    JSONArray getProblemByIp(String ip, Long time, boolean recent);
}
