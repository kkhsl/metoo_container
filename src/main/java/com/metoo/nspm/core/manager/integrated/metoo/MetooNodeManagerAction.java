package com.metoo.nspm.core.manager.integrated.metoo;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.TopoNodeDto;
import com.github.pagehelper.Page;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.entity.nspm.TopoNode;
import com.metoo.nspm.entity.nspm.User;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RequestMapping("/nspm/metoo/node")
@RestController
public class MetooNodeManagerAction {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IUserService userService;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private INodeService nodeService;
    @Autowired
    private IDeviceService deviceService;



    @ApiOperation("历史节点同步")
    @RequestMapping("/nodeQuery/backup")
    public Object nodeQuery1(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/queryNode.action";
            if(dto.getBranchLevel() == null || dto.getBranchLevel().equals("")){
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                dto.setBranchLevel(user.getGroupLevel());
            }
            Object result = this.nodeUtil.getBody(dto, url, token);
            JSONObject object = JSONObject.parseObject(result.toString());
            if(object != null){
                List list = new ArrayList();
                if(object.get("data") != null){
                    JSONArray arrays = JSONArray.parseArray(object.get("data").toString());
                    for(Object array : arrays){
                        JSONObject data = JSONObject.parseObject(array.toString());
                        String hostAddress = data.get("ip").toString();
                        TopoNode topoNode = new TopoNode();
//                        BeanUtils.copyProperties(data, topoNode);

                        topoNode = JSONObject.toJavaObject(data, topoNode.getClass());
                        topoNode.setHostAddress(hostAddress);
                        if(data.get("branchLevel") != null){
                            Group group = this.groupService.getObjByLevel(data.get("branchLevel").toString());
                            if(group != null){

                                topoNode.setBranchId(group.getId());
                                topoNode.setBranchName(group.getBranchName());
                                topoNode.setBranchLevel(group.getLevel());
                            }
                        }else{
                            User user = ShiroUserHolder.currentUser();
                            topoNode.setBranchId(user.getGroupId());
                            topoNode.setBranchName(user.getGroupName());
                            topoNode.setBranchLevel(user.getGroupLevel());
                        }
                        if(data.get("type") != null){
                            String type = data.get("type").toString();
                            if(type.equals("3")){
                                topoNode.setVendorName("觅通");
                            }

                        }
                        // 检测Ip是否已存在
                        TopoNode obj = this.nodeService.getObjByHostAddress(topoNode.getHostAddress());
                        if(obj != null){
                            this.nodeService.update(topoNode);
                        }else{
                            topoNode.setNodeId(Long.valueOf(data.get("id").toString()));
                            this.nodeService.save(topoNode);
                        }
                    }

                }
            }
            return ResponseUtil.ok();
        }
        return ResponseUtil.error();
    }

    @ApiOperation("节点列表")
    @RequestMapping("/nodeQuery")
    public Object nodeQuery(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null) {
            String url = "/topology/node/queryNode.action";

            if (dto.getBranchLevel() == null || dto.getBranchLevel().equals("")) {
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                dto.setBranchLevel(user.getGroupLevel());
            }
            // 分页查询
            Page<TopoNode> page = this.nodeService.query(dto);
            if (page.getResult().size() > 0) {
                // 遍历Topo
                List<TopoNode> topoNodes = page.getResult();
                for (TopoNode topoNode : topoNodes) {
                    if (topoNode.getState() == -1 || topoNode.getState() == -2) {
                        // 获取安博通节点信息，更新采集状态
                        dto.setFilter(topoNode.getHostAddress());
                        dto.setState(null);
                        Object object = this.nodeUtil.getBody(dto, url, token);
                        JSONObject result = JSONObject.parseObject(object.toString());
                        if (!result.get("total").toString().equals("0")) {
                            if (result.get("data") != null) {
                                JSONArray arrays = JSONArray.parseArray(result.get("data").toString());
                                for (Object array : arrays) {
                                    JSONObject data = JSONObject.parseObject(array.toString());
                                    if (Integer.parseInt(data.get("state").toString()) != topoNode.getState()) {
                                        topoNode.setState(Integer.parseInt(data.get("state").toString()));
                                        this.nodeService.update(topoNode);
                                    }
                                }
                            }
                        }
                    }
                }
                return ResponseUtil.ok(new PageInfo<TopoNode>(page));
            }
        }
        return ResponseUtil.ok();
    }

    /**
     * 节点关联组(联表查询)
     * @param dto
     * @return
     */
    @ApiOperation("节点保存(local)")
    @RequestMapping("/addGatherNode")
    public Object addGatherNodeLocal(TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/addGatherNode.action";
            Object object = this.nodeUtil.getBody(dto, url, token);
            // 同步节点到本地(检测ip是否已存储在，存在则为更新)
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("result") != null && Boolean.valueOf(result.get("result").toString())){
                TopoNode topoNode = new TopoNode();

                BeanUtils.copyProperties(dto, topoNode);
                // 根据等级查询等级信息
                Group group = this.groupService.getObjByLevel(dto.getBranchLevel());
                topoNode.setBranchId(group.getId());
                topoNode.setBranchName(group.getBranchName());
                topoNode.setBranchLevel(group.getLevel());
                if(group == null){
                    User user = ShiroUserHolder.currentUser();
                    topoNode.setBranchId(user.getGroupId());
                    topoNode.setBranchName(user.getGroupName());
                    topoNode.setBranchLevel(user.getGroupLevel());
                }
                // 检测Ip是否已存在
                TopoNode obj = this.nodeService.getObjByHostAddress(topoNode.getHostAddress());
                if(obj != null){
                    this.nodeService.update(topoNode);
                }else{
                    topoNode.setAddTime(new Date());
                    this.nodeService.save(topoNode);
                }
            }
            // 新增节点,更新Vendor表

            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("编辑保存（防火墙）")
    @RequestMapping("/updateNode")
    public Object updateNode(TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/updateNode.action";
            Object object = this.nodeUtil.getBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(Boolean.valueOf(result.get("result").toString())){
                // 同步信息到本地
                TopoNode topoNode = new TopoNode();
                BeanUtils.copyProperties(dto, topoNode);
                // 根据等级查询等级信息
                Group group = this.groupService.getObjByLevel(dto.getBranchLevel());
                topoNode.setBranchId(group.getId());
                topoNode.setBranchName(group.getBranchName());
                topoNode.setBranchLevel(group.getLevel());
                if(group == null){
                    User user = ShiroUserHolder.currentUser();
                    topoNode.setBranchId(user.getGroupId());
                    topoNode.setBranchName(user.getGroupName());
                    topoNode.setBranchLevel(user.getGroupLevel());
                }
                this.nodeService.update(topoNode);
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.error();
    }

    @ApiOperation("节点删除")
    @RequestMapping("/nodeDelete")
    public Object nodeDelete(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/nodeDelete.action";
            TopoNode topoNode = this.nodeService.getObjById(Long.parseLong(dto.getId()));
            if(topoNode != null){
                Object object = this.nodeUtil.getBody(dto, url, token);
                Long id = topoNode.getId();
                dto.setId(topoNode.getNodeId().toString());
                JSONObject result = JSONObject.parseObject(object.toString());
                if(result.get("result").toString().equals("true")){
                    // 删除本地节点

                    this.nodeService.delete(id);
                    return ResponseUtil.ok();
                }
                return ResponseUtil.error();
            }
        }
        return ResponseUtil.badArgument();
    }

}
