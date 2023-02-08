package com.metoo.nspm.core.manager.admin.action;

import com.github.pagehelper.Page;
import com.github.pagehelper.util.StringUtil;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.IHostService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.HostDTO;
import com.metoo.nspm.entity.nspm.Host;
import com.metoo.nspm.entity.nspm.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequestMapping("/admin/host")
@RestController
public class HostManagerController {

    @Autowired
    private IHostService hostService;

    public static void main(String[] args) {
        String ids = null;
        if(!StringUtil.isEmpty(ids)){
            System.out.println("true");
        }else{
            System.out.println("false");
        }
    }

    @RequestMapping("/list")
    public Object list(HostDTO dto){
        if(dto == null){
            dto = new HostDTO();
        }
        User user = ShiroUserHolder.currentUser();
        dto.setUserId(user.getId());
        Page<Host> page = this.hostService.selectConditionQuery(dto);
        if(page.getResult().size() > 0){
            return ResponseUtil.ok(new PageInfo<Host>(page));
        }
        return ResponseUtil.ok();
    }

    @GetMapping("/update")
    public Object update(@RequestParam(value = "id") Long id){
        User user = ShiroUserHolder.currentUser();
        Map params = new HashMap();
        params.put("id", id);
        params.put("userId", user.getId());
        List<Host> list = this.hostService.selectObjByMap(params);
        if(list.size() > 0){
            return ResponseUtil.ok(list.get(0));
        }
        return ResponseUtil.badArgument();
    }

    @PostMapping("/save")
    public Object save(@RequestBody(required = false) Host host){
        User user = ShiroUserHolder.currentUser();
        if(host.getName() == null || host.getName().equals("")){
            return ResponseUtil.badArgument("主机名称不能为空");
        }else{
            Map params = new HashMap();
            params.put("hostId", host.getId());
            params.put("name", host.getName());
            List<Host> hosts = this.hostService.selectObjByMap(params);
            if(hosts.size() > 0){
                return ResponseUtil.badArgument("主机名称已存在");
            }
        }
        if(!StringUtil.isEmpty(host.getIp1())){
            host.setIp1(IpUtil.ipConvertDec(host.getIp1()));
        }
        if(!StringUtil.isEmpty(host.getIp2())){
            host.setIp2(IpUtil.ipConvertDec(host.getIp2()));
        }
        int i = this.hostService.save(host);
        if(i >= 1){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.error();
        }
    }

    @DeleteMapping("/delete")
    public Object delete(String ids){
        if(!StringUtil.isEmpty(ids)){
            for (String id : ids.split(",")) {
                Host host = this.hostService.selectObjById(Long.parseLong(id));
                if(host != null){
                    try {
                        this.hostService.delete(Long.parseLong(id));
                        continue;
                    } catch (NumberFormatException e) {
                        e.printStackTrace();
                        return ResponseUtil.error();
                    }
                }
                return ResponseUtil.badArgument("请选择正确id");
            }
            return ResponseUtil.ok();
        }
        return ResponseUtil.badArgument("请输入必填参数");
    }
}
