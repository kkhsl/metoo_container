package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.manager.admin.tools.GroupTools;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.IDomainService;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.Domain;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RequestMapping("/admin/domain")
@RestController
public class DomainManagerController {

    @Autowired
    private IDomainService domainService;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private GroupTools groupTools;

    @GetMapping
    public Object list(){
        Map params = new HashMap();
        List<Domain> domains = this.domainService.selectObjByMap(params);
        return ResponseUtil.ok(domains);
    }

    @PostMapping
    public Object save(@RequestBody Domain domain){
        if(domain.getName() == null || domain.getName().equals("")){
            return ResponseUtil.badArgument("名称不能为空");
        }else{
            Map params = new HashMap();
            params.put("domainId", domain.getId());
            params.put("name", domain.getName());
            // 当前分组内不重名
            User user = ShiroUserHolder.currentUser();
            Group group = this.groupService.selectObjById(user.getGroupId());
            if(group != null) {
                Set<Long> ids = this.groupTools.genericGroupId(group.getId());
                params.put("groupIds", ids);
            }
            List<Domain> domains = this.domainService.selectObjByMap(params);
            if(domains.size() > 0){
                return ResponseUtil.badArgument("名称重复");
            }
        }
        int result = this.domainService.save(domain);
        if(result >= 1){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error();
    }

    @DeleteMapping
    public Object delete(String ids){
        for (String id : ids.split(",")){
            Domain domain = this.domainService.selectObjById(Long.parseLong(id));
            if(domain == null){
                return ResponseUtil.badArgument();
            }
            int i = this.domainService.delete(Long.parseLong(id));
            if(i <= 0){
                return ResponseUtil.error();
            }
        }
        return ResponseUtil.ok();
    }

    @GetMapping("/domain")
    public Object domain(){
        List<Domain> domains = this.domainService.selectDomainAndVlanProceDureByMap(null);
        return ResponseUtil.ok(domains);
    }

}
