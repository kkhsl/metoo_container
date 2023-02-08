package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;
import java.util.List;

@ApiModel("L2Domian")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class Domain extends IdEntity {

    private String name;
    private Integer number;
    private String description;
    private Date editDate;
    private Long groupId;
    private List<Vlan> vlans;
}
