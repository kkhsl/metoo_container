package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.IHomeService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.Home;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequestMapping("/admin/home")
@RestController
public class HomeManagerController {

    @Autowired
    private IHomeService homeService;

    @GetMapping
    public Object list(){
        Map params = new HashMap();// 传递orderBy排序无效
//        params.put("orderBy", "sequence");
//        params.put("orderType", "desc");
        List<Home> homes = this.homeService.selectObjByMap(params);
        return ResponseUtil.ok(homes);
    }

    @PostMapping
    public Object save(@RequestBody Home home){
        int i = this.homeService.save(home);
        if(i >= 1){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.error();
        }
    }

    @DeleteMapping
    public Object delete(@RequestParam Long id){
        int i = this.homeService.delete(id);
        if(i >= 1){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.error();
        }
    }
}
