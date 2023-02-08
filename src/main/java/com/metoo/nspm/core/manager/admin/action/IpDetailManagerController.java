package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.IpDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/admin/ip")
@RestController
public class IpDetailManagerController {

    @Autowired
    private IpDetailService ipDetailService;

//    @GetMapping("/update")
//    public void update(@RequestParam(value = "id") Long id){
//    }
}
