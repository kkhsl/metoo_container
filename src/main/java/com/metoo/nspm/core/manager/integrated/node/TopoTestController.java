package com.metoo.nspm.core.manager.integrated.node;

import com.metoo.nspm.core.service.topo.ITopoNodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TopoTestController {

    @Autowired
    private ITopoNodeService topoNodeService;

    @RequestMapping("/topoNode")
    public void topoNode(){
        this.topoNodeService.queryNetworkElement().forEach(item -> System.out.println(item));
    }


}
