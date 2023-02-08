package com.metoo.nspm.dto;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("分组")
public class BranchDto {

    private String id;
    private String branchName;
    private String branchDesc;
    private String parentLevel;
}
