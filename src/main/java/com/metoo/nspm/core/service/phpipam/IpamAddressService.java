package com.metoo.nspm.core.service.phpipam;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.entity.Ipam.IpamAddress;

public interface IpamAddressService {

    JSONObject addresses(Integer id, String path);

    JSONObject create(IpamAddress instance);

    JSONObject update(IpamAddress instance);

    JSONObject remove(Integer id, String path);




}
