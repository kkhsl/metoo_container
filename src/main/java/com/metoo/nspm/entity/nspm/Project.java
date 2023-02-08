package com.metoo.nspm.entity.nspm;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;

@ApiModel("项目管理")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class Project extends IdEntity {

    private String name;
    @JsonFormat(pattern = "yyyy-MM-dd",timezone = "GMT+8")
    private Date startTime;
    @JsonFormat(pattern = "yyyy-MM-dd",timezone = "GMT+8")
    private Date acceptTime;
    private String personLiable;
    private String description;
    private Long userId;
    private String userName;
}
