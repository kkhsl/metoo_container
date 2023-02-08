package com.metoo.nspm.core.config.global;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.nspm.ILicenseService;
import com.metoo.nspm.entity.nspm.License;
import com.metoo.nspm.vo.Result;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LicenseFilter implements Filter {

    @Autowired
    private ILicenseService licenseService;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        // 检测授权码
        License license = this.licenseService.detection();
        if(license != null && license.getStatus() == 0 && license.getFrom() == 0){
            chain.doFilter(servletRequest, servletResponse);
        }else{
            HttpServletRequest request = (HttpServletRequest) servletRequest;
            System.out.println(request.getRequestURI());
            System.out.println(request.getRequestURL());
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            String message = "未授权";
            if(license != null){
                switch (license.getStatus()){
                    case 1:
                        message = "未授权";
                        break;
                    case 2:
                        message = "授权已过期";
                        break;
                }
            }
            Result result = new Result(413, message);
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json");
            response.getWriter().print(JSONObject.toJSONString(result));
        }
      }

    @Override
    public void destroy() {

    }
}
