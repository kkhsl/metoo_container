package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.Accessory;

import java.util.List;
import java.util.Map;

public interface IAccessoryService {

    Accessory getObjById(Long id);

    int save(Accessory instance);

    int update(Accessory instance);

    int delete(Long id);

    List<Accessory> query(Map params);
}
