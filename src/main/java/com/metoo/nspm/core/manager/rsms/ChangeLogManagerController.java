package com.metoo.nspm.core.manager.rsms;

import com.metoo.nspm.core.service.nspm.IChangeLogService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.ChangeLogDto;
import com.metoo.nspm.entity.nspm.ChangeLog;
import com.github.pagehelper.Page;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/admin/rsms/change/log")
@RestController
public class ChangeLogManagerController {

    @Autowired
    private IChangeLogService changeLogService;

    @RequestMapping("/list")
    public Object list(@RequestBody(required = false)ChangeLogDto instance){
        Page<ChangeLog> page = this.changeLogService.findBySelect(instance);
        if(page.size() > 0){
            return ResponseUtil.ok(new PageInfo<ChangeLogDto>(page));
        }
        return ResponseUtil.ok();
    }
}
