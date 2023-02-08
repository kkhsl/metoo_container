package com.metoo.nspm.core.service.api.zabbix;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.dto.zabbix.UserMacroDTO;

public interface IUserMacroService {

    JSONObject getUserMacro(UserMacroDTO dto);

    JSONArray getUserMacros(UserMacroDTO dto);

    JSONObject updateUserMacros(UserMacroDTO dto);
}
