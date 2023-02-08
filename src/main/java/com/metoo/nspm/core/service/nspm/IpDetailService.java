package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.IpDetail;

import java.util.List;
import java.util.Map;

public interface IpDetailService  {


    IpDetail selectObjByIp(String ip);

    List<IpDetail> selectObjByMap(Map map);

    IpDetail selectObjByMac(String mac);


    int save(IpDetail instance);

    int update(IpDetail instance);
}
