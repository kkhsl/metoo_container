package com.metoo.nspm.core.manager.admin.tools;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.springframework.stereotype.Component;

@Component
public class Md5Crypt {

    public String md5(String str, String salt){
        Md5Hash md5Hash = new Md5Hash(str, salt);
        return md5Hash.toHex();
    }
}
