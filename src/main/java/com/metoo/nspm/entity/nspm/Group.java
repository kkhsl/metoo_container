package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;
import java.util.List;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("用户组")
public class Group extends IdEntity {

    @ApiModelProperty("组名称")
    private String branchName;
    @ApiModelProperty("组等级")
    private String level;
    @ApiModelProperty("组备注")
    private String branchDesc;
    @ApiModelProperty("所属父级")
    private Long parentId;
    @ApiModelProperty("父等级")
    private String parentLevel;
    @ApiModelProperty("子集")
    private List<Group> branchList;
    @ApiModelProperty("更新时间")
    private Date updateTime;
}
