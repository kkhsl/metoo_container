package com.metoo.nspm.core.manager.view.action;

import com.metoo.nspm.core.video.ChangeVideo;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("convert/")
public class ConvertAction {

    @RequestMapping("/begin")
    public boolean convert(){
       /* return ChangeVideo.convert("C:\\Users\\46075\\Desktop\\20210323040120436\\merge.ts",
                "C:\\Users\\46075\\Desktop\\20210323040120436\\temp.mp4");*/
        return ChangeVideo.convert("/www/wwwroot/test/merge.ts",
                "/www/wwwroot/test/temp.mp4");
    }
}
