package com.metoo.nspm.core.service.phpipam;

import com.alibaba.fastjson.JSONObject;

public interface IpamSectionService {

    JSONObject sections(Integer id, String path);

    Integer getSectionsId();
}
