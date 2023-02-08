package com.metoo.nspm.core.service.api.zabbix;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.dto.zabbix.TriggerDTO;
import com.metoo.nspm.dto.zabbix.UserMacroDTO;

public interface ITriggerService {

    JSONObject get(TriggerDTO dto);

    JSONObject create(TriggerDTO dto);

    JSONObject update(TriggerDTO dto);

    JSONObject delete(TriggerDTO dto);

    JSONObject createTrigger(TriggerDTO dto);

    JSONObject updateTrigger(TriggerDTO dto);

    JSONObject deleteTrigger(TriggerDTO dto);

}
