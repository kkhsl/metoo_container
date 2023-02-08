package com.metoo.nspm.core.service.phpipam;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.entity.Ipam.IpamVlan;

public interface IpamVlanService {

    Object vlan(Integer id);

    Object vlanSubnets(Integer id);

    JSONObject create(IpamVlan instance);

    JSONObject update(IpamVlan instance);

    JSONObject remove(Integer id, String path);
}
