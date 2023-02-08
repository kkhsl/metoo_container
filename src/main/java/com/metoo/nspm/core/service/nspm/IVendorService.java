package com.metoo.nspm.core.service.nspm;


import com.metoo.nspm.entity.nspm.Vendor;

import java.util.List;
import java.util.Map;

public interface IVendorService {

    Vendor selectObjById(Long id);

    Vendor selectObjByName(String name);

    List<Vendor> selectConditionQuery(Map params);
}
