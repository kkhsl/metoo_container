package com.metoo.nspm.dto;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("AssetDto")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class Risk {

    private List uuids;
}
