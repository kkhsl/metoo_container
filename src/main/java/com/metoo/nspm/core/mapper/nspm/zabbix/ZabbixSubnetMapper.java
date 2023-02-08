package com.metoo.nspm.core.mapper.nspm.zabbix;

import com.metoo.nspm.entity.nspm.Subnet;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface ZabbixSubnetMapper {


    Subnet selectObjById(Long id);

    Subnet selectObjByIp(@Param("ip") String ip, @Param("mask") Integer mask);

    List<Subnet> selectSubnetByParentId(Long id);

    List<Subnet> selectSubnetByParentIp(Long ip);

    int save(Subnet instance);

    int update(Subnet instance);

    int delete(Long id);

}
