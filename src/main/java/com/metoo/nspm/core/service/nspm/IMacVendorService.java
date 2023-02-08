package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.MacVendor;

import java.util.List;
import java.util.Map;

public interface IMacVendorService {

    List<MacVendor> selectObjByMap(Map params);
}
