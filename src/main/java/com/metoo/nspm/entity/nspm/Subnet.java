package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class Subnet extends IdEntity {

    private String ip;
    private Integer mask;
    private Long parentId;
    private String parentIp;
    private List<Subnet> subnetList;
    private String vlan;
    private Long vlanId;
    private String vlanName;
    private String threshold;
    private String description;
    private Object picture;


}
