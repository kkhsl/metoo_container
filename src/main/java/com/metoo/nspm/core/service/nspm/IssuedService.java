package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.Policy;
import com.metoo.nspm.entity.nspm.Task;

import java.util.List;

public interface IssuedService {

    void pushtaskstatuslist();

    List<Task> query();

    void queryTask(String invisibleName, String type, List<Policy> policysNew, String command);

    void createOrder(String userName, String type, List<Policy> policysNew);
}
