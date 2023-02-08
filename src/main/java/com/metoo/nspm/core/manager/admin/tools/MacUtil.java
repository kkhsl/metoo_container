package com.metoo.nspm.core.manager.admin.tools;

import com.metoo.nspm.core.service.nspm.IMacVendorService;
import com.metoo.nspm.entity.nspm.Mac;
import com.metoo.nspm.entity.nspm.MacVendor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class MacUtil {

    @Autowired
    private IMacVendorService macVendorService;

    public List<Mac> macJoint(List<Mac> macs){
        if(macs != null && macs.size() > 0) {
            for (Mac mac : macs) {
                if (mac.getMac() != null && !mac.getMac().equals("")) {
                    String macAddr = mac.getMac();
                    int one_index = macAddr.indexOf(":");
                    String one = macAddr.substring(0, one_index);
                    if (one.equals("0")) {
                        one = "00";
                    }
                    int tow_index = macAddr.indexOf(":", one_index + 1);
                    String two = macAddr.substring(one_index, tow_index);
                    if (two.equals("0")) {
                        two = "00";
                    }
                    int three_index = macAddr.indexOf(":", tow_index + 1);
                    String three = macAddr.substring(tow_index, three_index);
                    if (three.equals("0")) {
                        three = "00";
                    }
                    macAddr = one + two + three;
                    Map params = new HashMap();
                    params.clear();
                    params.put("mac", macAddr);
                    List<MacVendor> macVendors = this.macVendorService.selectObjByMap(params);
                    if (macVendors.size() > 0) {
                        MacVendor macVendor = macVendors.get(0);
                        mac.setVendor(macVendor.getVendor());
                    }
                }
            }
        }
        return macs;
    }
}
