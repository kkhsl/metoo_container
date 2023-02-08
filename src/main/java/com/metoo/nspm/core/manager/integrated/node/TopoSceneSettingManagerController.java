package com.metoo.nspm.core.manager.integrated.node;

import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.SceneDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.entity.nspm.User;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

//@RequiresPermissions("LK:SCENE:MANAGER")
@Api("场景设置")
@RequestMapping("/nspm/scene")
@RestController
public class TopoSceneSettingManagerController {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private NodeUtil nodeUtil;
    private SceneDto dto;
    @Autowired
    private IUserService userService;

    @ApiOperation("场景列表")
    @PostMapping(value = "/push/api/disposal/scenes/pageList")
    public Object list(@RequestBody(required = false) SceneDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/api/disposal/scenes/pageList";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("场景新建")
    @PostMapping(value = "/push/api/disposal/scenes/edit")
    public Object edit(@RequestBody(required = false) SceneDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/api/disposal/scenes/edit";
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            dto.setCreateUser(user.getUsername());
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("场景编辑")
    @PostMapping(value = "/push/api/disposal/scenes/getByUUId")
    public Object getByUUId(@RequestBody(required = false) SceneDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/api/disposal/scenes/getByUUId";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("场景删除")
    @PostMapping(value = "/push/api/disposal/scenes/delete")
    public Object delete(@RequestBody(required = false) SceneDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String[] ids = dto.getIds().split(",");
            if(ids.length>0){
                String url = "/push/api/disposal/scenes/delete";
                for(String id : ids){
                    SceneDto obj = new SceneDto();
                    obj.setId(Integer.parseInt(id));
                    this.nodeUtil.postFormDataBody(obj, url, token);
                }
                return ResponseUtil.ok();
            }
            return ResponseUtil.ok();
        }
        return ResponseUtil.error();
    }

}
