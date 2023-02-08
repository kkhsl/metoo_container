package com.metoo.nspm.core.manager.zabbix.action;

import com.github.pagehelper.Page;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.zabbix.IProblemService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.NetworkElementDto;
import com.metoo.nspm.dto.NspmProblemDTO;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.NetworkElement;
import com.metoo.nspm.entity.nspm.User;
import com.metoo.nspm.entity.zabbix.Interface;
import com.metoo.nspm.entity.zabbix.Problem;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RequestMapping("/admin/zabbix/problem")
@RestController
public class ProblemManagerController {

    @Autowired
    private IProblemService problemService;

    @ApiOperation("告警信息")
    @GetMapping
    public Object problem(@RequestParam(required = false) String ip,
                          @RequestParam(required = false) Integer limit) {
        Map params = new HashMap();
        params.put("ip", ip);
        params.put("limit", limit);
        List<Problem> problemList = this.problemService.selectObjByMap(params);
        return ResponseUtil.ok(problemList);
    }

    @ApiOperation("告警信息")
    @GetMapping
    @RequestMapping("/list")
    public Object list(@RequestBody(required = false) NspmProblemDTO dto) {
        if (dto == null) {
            dto = new NspmProblemDTO();
        }
        Page<Problem> page = this.problemService.selectConditionQuery(dto);
        if (page.getResult().size() > 0) {
            // 获取主机状态
            return ResponseUtil.ok(new PageInfo<Problem>(page));

        }
        return ResponseUtil.ok();
    }

}
