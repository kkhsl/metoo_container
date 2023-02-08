package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.manager.admin.tools.GroupTools;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.core.service.nspm.IPresetPathService;
import com.metoo.nspm.core.service.nspm.ITopologyService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.PresetPathDTO;
import com.github.pagehelper.Page;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.PresetPath;
import com.metoo.nspm.entity.nspm.Topology;
import com.metoo.nspm.entity.nspm.User;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Api("预置路径管理")
@RequestMapping("/admin/path")
@RestController
public class PresetPathManagerController {

    @Autowired
    private IPresetPathService presetPathService;
    @Autowired
    private ITopologyService topologyService;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private GroupTools groupTools;

    @ApiOperation("列表")
    @PostMapping("/list")
    public Object list(@RequestBody(required = false) PresetPathDTO dto){
        if(dto == null){
            dto = new PresetPathDTO();
        }
        User user = ShiroUserHolder.currentUser();
        dto.setUserId(user.getId());
        Page<PresetPath> page = this.presetPathService.selectConditionQuery(dto);
        if(page.getResult().size() > 0){
            return ResponseUtil.ok(new PageInfo<PresetPath>(page));
        }
        return  ResponseUtil.ok();
    }

    @ApiOperation("添加")
    @GetMapping("/add")
    public Object add(){
        User user = ShiroUserHolder.currentUser();
        Map params = new HashMap();
        params.put("userId", user.getUsername());
        Map map = new HashMap();
        // topology列表
        params.clear();
        Group group = this.groupService.selectObjById(user.getGroupId());
        if(group != null) {
            Set<Long> ids = this.groupTools.genericGroupId(group.getId());
            params.put("groupIds", ids);
            List<Topology> topologies = this.topologyService.selectObjByMap(params);
            map.put("topologyList", topologies);
        }
        return  ResponseUtil.ok(map);
    }


    @ApiOperation("编辑")
    @GetMapping("/update")
    public Object update(@RequestParam(value = "id") Long id){
        User user = ShiroUserHolder.currentUser();
        Map params = new HashMap();
        params.put("id", id);
        params.put("userId", user.getId());
        List<PresetPath> presetPaths = this.presetPathService.selectObjByMap(params);
        if(presetPaths.size() > 0){
            Map map = new HashMap();
            // topology列表
            params.clear();
            Group group = this.groupService.selectObjById(user.getGroupId());
            if(group != null) {
                Set<Long> ids = this.groupTools.genericGroupId(group.getId());
                params.put("groupIds", ids);
                List<Topology> topologies = this.topologyService.selectObjByMap(params);
                map.put("topologyList", topologies);
            }

            map.put("presetPath", presetPaths.get(0));

            return  ResponseUtil.ok(map);
        }
        return  ResponseUtil.badArgument();
    }

    @ApiOperation("新增/修改")
    @PostMapping("/save")
    public Object save(@RequestBody(required = false) PresetPathDTO instance){
        // 验证名称是否已存在
        if(instance.getName() == null || instance.getName().equals("")){
            return ResponseUtil.badArgument();
        }else{
            // 校验名称是否重复
            Map params = new HashMap();
            params.put("presetPathId", instance.getId());
            params.put("name", instance.getName());
            List<PresetPath> persetPaths = this.presetPathService.selectObjByMap(params);
            if(persetPaths.size() > 0){
                return ResponseUtil.badArgumentRepeatedName();
            }
        }
        // 验证ip合法性
        boolean src =  IpUtil.verifyIp(instance.getSrcIp());
        if(!src){
            return ResponseUtil.badArgument("源ip不合法");
        }
        // 验证ip合法性
        boolean dest =  IpUtil.verifyIp(instance.getDestIp());
        if(!dest){
            return ResponseUtil.badArgument("目的ip不合法");
        }
        // 校验topo
        Topology topology = this.topologyService.selectObjById(instance.getTopologyId());
        if(topology != null){
            instance.setTopologyName(topology.getName());
        }else{
            instance.setTopologyId(null);
        }

        // 拼接content
        StringBuffer stringBuffer = new StringBuffer();
        if(instance.getSrcIp() != null){
//            String mask = "";
//            if(instance.getSrcMask() != null && !instance.getSrcMask().equals("")){
//                mask = IpUtil.bitMaskConvertMask(Integer.parseInt(instance.getSrcMask()));
//            }else{
//                mask = "255.255.255.0";
//            }
//            // 获取子网
//            Map<String, String> map = IpUtil.getNetworkIp(instance.getSrcIp(), mask);
//            String subnet = map.get("network");
//            stringBuffer.append("源子网:").append(subnet);
            stringBuffer.append("源ip:").append(instance.getSrcIp());
            if(instance.getSrcMask() != null && !instance.getSrcMask().equals("")){
                stringBuffer.append("/" + instance.getSrcMask());
            }
        }
        if(instance.getDestIp() != null || instance.getDestMask() != null){
            stringBuffer.append("目的ip:").append(instance.getDestIp()).append("/" + instance.getDestMask());
        }
        instance.setContent(stringBuffer.toString());
        PresetPath presetPath = new PresetPath();
        BeanUtils.copyProperties(instance, presetPath);
        User user = ShiroUserHolder.currentUser();
        presetPath.setUserId(user.getId());
        presetPath.setUserName(user.getUsername());
        int i = this.presetPathService.save(presetPath);
        if(i >= 1){
            return ResponseUtil.ok();
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("删除")
    @DeleteMapping("/delete")
    public Object delete(@RequestParam(value = "ids") String ids){
        User user = ShiroUserHolder.currentUser();
        for (String id : ids.split(",")){
            Map params = new HashMap();
            params.put("id", id);
            params.put("userId", user.getId());
            List<PresetPath> presetPaths = this.presetPathService.selectObjByMap(params);
            if(presetPaths.size() > 0){
                this.presetPathService.delete(Long.parseLong(id));
            }else{
                return ResponseUtil.badArgument();
            }
        }
        return ResponseUtil.ok();
    }



}
