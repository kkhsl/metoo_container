package com.metoo.nspm.core.manager.admin.action;

import com.github.pagehelper.Page;
import com.github.pagehelper.util.StringUtil;
import com.metoo.nspm.core.manager.admin.tools.GroupTools;
import com.metoo.nspm.core.service.nspm.ICredentialService;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.CredentialDTO;
import com.metoo.nspm.dto.NetworkElementDto;
import com.metoo.nspm.entity.nspm.Credential;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.NetworkElement;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/admin/credential")
public class CredentialManagerController {

    @Autowired
    private ICredentialService credentialService;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private GroupTools groupTools;

    @ApiOperation("凭据列表")
    @PostMapping("/list")
    public Object list(@RequestBody(required = true) CredentialDTO dto){
        if(dto == null){
            dto = new CredentialDTO();
        }
        if(dto.getGroupId() != null){
            Group group = this.groupService.selectObjById(dto.getGroupId());
            if(group != null){
                Set<Long> ids = this.groupTools.genericGroupId(group.getId());
                dto.setGroupIds(ids);
            }
        }
        Page<Credential> page = this.credentialService.selectObjByConditionQuery(dto);
        if(page.getResult().size() > 0){
            // setGroupName
            for(Credential credential : page.getResult()){
                Group group = this.groupService.selectObjById(credential.getGroupId());
                if(group != null){
                    credential.setGroupName(group.getBranchName());
                }
            }
            return ResponseUtil.ok(new PageInfo<Credential>(page));
        }
        return ResponseUtil.ok();
    }

    @ApiOperation("凭据添加")
    @PostMapping("/save")
    public Object save(@RequestBody Credential instance){
        if(StringUtils.isEmpty(instance.getName())){
            return ResponseUtil.badArgument("凭据名不能为空");
        }
        if(StringUtils.isEmpty(instance.getLoginName())){
            return ResponseUtil.badArgument("登录名不能为空");
        }
//        if(StringUtils.isEmpty(instance.getLoginPassword())){
//            return ResponseUtil.badArgument("登录密码不能为空");
//        }
        if(instance.isTrafficPermit()){
            if(StringUtil.isEmpty(instance.getEnableUserName())){
                return ResponseUtil.badArgument("通行用户名不能为空");
            }
            if(StringUtil.isEmpty(instance.getEnablePassword())){
                return ResponseUtil.badArgument("通行密码不能为空");
            }
        }else{
            instance.setEnablePassword(null);
            instance.setEnableUserName(null);
        }
        if(instance.getGroupId() != null){
            Group group = this.groupService.selectObjById(instance.getGroupId());
            if(group == null){
                return ResponseUtil.badArgument("分组id[" + instance.getGroupId() + "]，不存在");
            }
        }
        int i = this.credentialService.save(instance);
        if(i >= 1){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.error();
        }
    }

    @ApiOperation("删除/批量删除")
    @DeleteMapping
    public Object delete(@RequestParam(required = false, value = "id") Long id,@RequestParam(required = false, value = "ids") Long[] ids){
        if(ids != null && ids.length > 0){
            int i = this.credentialService.batchesDel(ids);
            if(i >= 1){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.error();
            }
        }else  if(id != null && !id.equals("")){
            int i = this.credentialService.delete(id);
            if(i >= 1){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.error();
            }
        }
        return ResponseUtil.badArgument();
    }

}
