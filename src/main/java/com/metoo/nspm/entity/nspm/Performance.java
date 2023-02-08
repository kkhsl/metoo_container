package com.metoo.nspm.entity.nspm;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Performance {

    private String id;
    private double total_flow;
    private double packet_loss;
    private double network;
    private double response;
    private double health;

}
