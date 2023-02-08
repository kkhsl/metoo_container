package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.IResService;
import org.apache.http.HttpRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Controller
public class MenuManagerController {

    @Autowired
    private IResService resService;

    @RequestMapping(value = "/test", headers = "api-version=1")
    @ResponseBody
    public Object test(HttpRequest request, HttpServletRequest request1){
        Collection<String> res = this.resService.findPermissionByUserId(Long.parseLong("23"));
        /*List<Map> params = new ArrayList();
        Cookie[] cookies = request1.getCookies();
        for (int i = 0; i < cookies.length; i++) {
            Map data = new HashMap();
            data.put("cookie", cookies[i].getValue());
            data.put("comment", cookies[i].getComment());
            data.put("domain", cookies[i].getDomain());
            data.put("maxAge", cookies[i].getMaxAge());
            data.put("name", cookies[i].getName());
            data.put("path", cookies[i].getPath());
            data.put("secure", cookies[i].getSecure());
            data.put("version", cookies[i].getVersion());
            params.add(data);
        }*/
        Map data = new HashMap();
        UUID uuid = UUID.randomUUID();
        data.put("uuid", uuid);

       return data;
    }

    @RequestMapping(value = "/test", headers = "api-version=2")
    @ResponseBody
    public Object test2(HttpRequest request, HttpServletRequest request1){
        Collection<String> res = this.resService.findPermissionByUserId(Long.parseLong("23"));
        /*List<Map> params = new ArrayList();
        Cookie[] cookies = request1.getCookies();
        for (int i = 0; i < cookies.length; i++) {
            Map data = new HashMap();
            data.put("cookie", cookies[i].getValue());
            data.put("comment", cookies[i].getComment());
            data.put("domain", cookies[i].getDomain());
            data.put("maxAge", cookies[i].getMaxAge());
            data.put("name", cookies[i].getName());
            data.put("path", cookies[i].getPath());
            data.put("secure", cookies[i].getSecure());
            data.put("version", cookies[i].getVersion());
            params.add(data);
        }*/
        Map data = new HashMap();
        UUID uuid = UUID.randomUUID();
        data.put("uuid", uuid + "2");

        return data;
    }
}
