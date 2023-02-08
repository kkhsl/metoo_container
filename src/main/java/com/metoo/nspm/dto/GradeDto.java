package com.metoo.nspm.dto;

import com.metoo.nspm.entity.nspm.Accessory;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.Accessors;

@ApiModel("年级DTO")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class GradeDto {

    private Long id;

    private String name;

    private int level;

    private int sequence;

    private String username;

    private Long user_id;

    private int type;

    private Long parent_id;

    private int display;

    private String message;

    private String a_name;

    private Accessory accessory;
}
