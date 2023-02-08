package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.utils.ResponseUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("admin/auth")
public class AdminAuthorController {

    @GetMapping("/401")
    public Object page401() {
        return ResponseUtil.unlogin();
    }

    @GetMapping("/403")
    public Object page403() {
        return ResponseUtil.unauthz();
    }

    @RequestMapping("imgUpload")
    public static boolean imageUpload(HttpServletRequest request, MultipartFile multipartFile, String path) throws FileNotFoundException {
       // String path = SystemTest.getProperty("user.dir") + File.separator + "resources" + File.separator + "static" + File.separator +"upload" + File.separator + "manager" ;
       /* String path = request.getSession()
                .getServletContext()
                .getRealPath("/");*/
        String paths = request.getParameter("path");
        Map<String, String[]> maps = request.getParameterMap();

        if(multipartFile == null && multipartFile.getSize() <= 0){
            return false;
        }
        //文件名
        String originalName = multipartFile.getOriginalFilename();
        String fileName= UUID.randomUUID().toString().replace("-", "");
        String picNewName = fileName + originalName.substring(originalName.lastIndexOf("."));
        String imgRealPath = path + picNewName;

        try {
            //保存图片-将multipartFile对象装入image文件中
            File imageFile=new File(imgRealPath);
            multipartFile.transferTo(imageFile);
            return true;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
    }
}
