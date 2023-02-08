package com.metoo.nspm.core.service.nspm;

import org.springframework.stereotype.Service;

@Service
public class TestInitService {

    private String a;

    public void init(){
        this.a="123";
    }

    public String getA(){
        return this.a;
    }


}
