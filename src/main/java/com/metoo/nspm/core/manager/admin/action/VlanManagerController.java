package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.manager.admin.tools.GroupTools;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.IDomainService;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.core.service.nspm.IVlanService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.Domain;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.User;
import com.metoo.nspm.entity.nspm.Vlan;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RequestMapping("/admin/vlan")
@RestController
public class VlanManagerController {

    @Autowired
    private IVlanService vlanService;
    @Autowired
    private IDomainService domainService;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private GroupTools groupTools;

    /**
     *
     * @param domainId 非必填，默认查询全部
     * @return
     */
    @GetMapping
    public Object list(@RequestParam(value = "domainId",required = false) Long domainId){
            User user = ShiroUserHolder.currentUser();
            Group group = this.groupService.selectObjById(user.getGroupId());
            if(group != null){
                Map params = new HashMap();
                Set<Long> ids = this.groupTools.genericGroupId(group.getId());
                params.put("groupIds", ids);
                Domain domain = this.domainService.selectObjById(domainId);
                if(domainId != null){
                    params.put("domainId", domain.getId());
                }
                List<Vlan> domains = this.vlanService.selectObjByMap(params);
                return ResponseUtil.ok(domains);

        }
        return ResponseUtil.ok();
    }

    @GetMapping("/add")
    public Object add(){
        Map params = new HashMap();
        List<Domain> domains = this.domainService.selectObjByMap(params);
        return ResponseUtil.ok(domains);
    }

    @GetMapping("/update")
    public Object updadte(@RequestParam(value = "id") Long id){
        Map map = new HashMap();
        Vlan vlan = this.vlanService.selectObjById(id);
        Domain domain = this.domainService.selectObjById(vlan.getDomainId());
        if(domain != null){
            vlan.setDomainName(domain.getName());
        }
        map.put("vlan", vlan);
        Map params = new HashMap();
        List<Domain> domains = this.domainService.selectObjByMap(params);
        map.put("Domain", domains);
        return ResponseUtil.ok(map);
    }

    @PostMapping
    public Object save(@RequestBody Vlan vlan){
        if(vlan.getName() == null || vlan.getName().equals("")){
            return ResponseUtil.badArgument("名称不能为空");
        }else{
            Map params = new HashMap();
            params.put("vlanId", vlan.getId());
            params.put("name", vlan.getName());
            // 当前分组内不重名
            User user = ShiroUserHolder.currentUser();
            Group group = this.groupService.selectObjById(user.getGroupId());
            if(group != null) {
                Set<Long> ids = this.groupTools.genericGroupId(group.getId());
                params.put("groupIds", ids);
            }
            List<Vlan> domains = this.vlanService.selectObjByMap(params);
            if(domains.size() > 0){
                return ResponseUtil.badArgument("名称重复");
            }
        }
        Domain domain = this.domainService.selectObjById(vlan.getDomainId());
        if(domain == null){
            return ResponseUtil.badArgument("请选择二层域");
        }
        int result = this.vlanService.save(vlan);
        if(result >= 1){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error();
    }

    @DeleteMapping
    public Object delete(String ids){
        for (String id : ids.split(",")){
            Vlan vlan = this.vlanService.selectObjById(Long.parseLong(id));
            if(vlan == null){
                return ResponseUtil.badArgument();
            }
            int i = this.vlanService.delete(Long.parseLong(id));
            if(i <= 0){
                return ResponseUtil.error();
            }
        }
        return ResponseUtil.ok();
    }
}
