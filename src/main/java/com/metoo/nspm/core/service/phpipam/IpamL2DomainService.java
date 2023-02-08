package com.metoo.nspm.core.service.phpipam;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.entity.Ipam.IpamDomain;

public interface IpamL2DomainService {

    JSONObject l2domains(Integer id);

    JSONObject vlans(Integer id);

    JSONObject create(IpamDomain instance);

    JSONObject update(IpamDomain instance);

    JSONObject remove(Integer id, String path);
}
