package com.metoo.nspm.core.manager.view.action;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/web")
@Controller
public class IndexViewController {

    @GetMapping("/index")
    public String index(Model model){
        model.addAttribute("msg", "强很烫");
        return "index";
    }
}
