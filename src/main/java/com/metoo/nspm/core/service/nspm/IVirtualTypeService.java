package com.metoo.nspm.core.service.nspm;


import com.metoo.nspm.entity.nspm.VirtualType;

import java.util.List;
import java.util.Map;

public interface IVirtualTypeService {

    VirtualType getObjById(Long id);

    List<VirtualType> selectByMap(Map map);
}
