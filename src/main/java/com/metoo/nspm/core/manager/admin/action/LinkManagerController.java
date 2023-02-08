package com.metoo.nspm.core.manager.admin.action;

import com.github.pagehelper.Page;
import com.metoo.nspm.core.manager.admin.tools.GroupTools;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.core.service.nspm.ILinkService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.LinkDTO;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.Link;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Field;
import java.util.Set;

@ApiOperation("链路管理")
@RestController
@RequestMapping("/admin/link")
public class LinkManagerController {

    @Autowired
    private ILinkService linkService;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private GroupTools groupTools;

    @GetMapping
    public Object list(@RequestBody(required = false) LinkDTO dto){
        if(dto == null){
            dto = new LinkDTO();
        }
        if(dto.getGroupId() != null){
            Group group = this.groupService.selectObjById(dto.getGroupId());
            if(group != null){
                Set<Long> ids = this.groupTools.genericGroupId(group.getId());
                dto.setGroupIds(ids);
            }
        }
        Page<Link> page = this.linkService.selectObjConditionQuery(dto);
        if(page.getResult().size() > 0) {
            return ResponseUtil.ok(new PageInfo<Link>(page));
        }
        return ResponseUtil.ok();
    }

    @PostMapping
    public Object save(@RequestBody(required = false) Link instance){
        if(this.checkObjAllFieldsIsNull(instance)){
            return ResponseUtil.ok();
        }
        int i = this.linkService.save(instance);
        if(i >= 1){
            return ResponseUtil.ok();
        }
        return ResponseUtil.badArgument();
    }

    public static boolean checkObjAllFieldsIsNull(Object object) {
        if (null == object) {
            return true;

        }
        try {
            for (Field f : object.getClass().getDeclaredFields()) {
                f.setAccessible(true);

                System.out.print(f.getName() + ":");

                System.out.println(f.get(object));

                if (f.get(object)!= null && StringUtils.isNotBlank(f.get(object).toString())) {
                    return false;
                }
            }
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @DeleteMapping
    public Object delete(@RequestParam(required = false, value = "id") String id, @RequestParam(required = false, value = "ids") Long[] ids){
        if(ids != null && ids.length > 0){
            int i = this.linkService.batchesDel(ids);
            if(i >= 1){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.error();
            }
        }else  if(id != null && !id.equals("")){
            int i = this.linkService.delete(Long.parseLong(id));
            if(i >= 1){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.error();
            }
        }
        return ResponseUtil.badArgument();
    }


}
