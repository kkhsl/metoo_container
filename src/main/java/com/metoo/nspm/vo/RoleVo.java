package com.metoo.nspm.vo;

import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Date;

@Data
@Accessors
public class RoleVo {

    private Long id;

    private Date addTime;

    private String name;

    private String roleCode;

    private String url;

    private String component;

    private Long roleGroupId;

    private String roleGroupName;

    private Long resId;

    private String resName;

}
