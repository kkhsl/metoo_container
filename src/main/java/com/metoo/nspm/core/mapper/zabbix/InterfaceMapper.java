package com.metoo.nspm.core.mapper.zabbix;

import com.metoo.nspm.entity.zabbix.Interface;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface InterfaceMapper {

    Interface selectObjByIp(String ip);

}
