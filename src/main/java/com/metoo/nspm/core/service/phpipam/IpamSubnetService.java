package com.metoo.nspm.core.service.phpipam;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.entity.Ipam.IpamSubnet;

public interface IpamSubnetService {

    JSONObject subnets(Integer id, String path);

    Integer getSubnetsBySubnet(String subnet, Integer mask);

    JSONObject create(IpamSubnet ipamSubnet);

    JSONObject update(IpamSubnet ipamSubnet);

    JSONObject remove(Integer id, String path);

}
