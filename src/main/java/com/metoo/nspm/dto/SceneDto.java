package com.metoo.nspm.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class SceneDto<T> {

    private Integer id;
    private Integer page;
    private Integer limit;
    private T disposalScenes;
    private String deviceJson;
    private String name;
    private String remarks;
    private String uuid;
    private String ids;
    private String branchLevel;
    private String createUser;
}
