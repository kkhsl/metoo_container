package com.metoo.nspm.core.utils.quartz;

import com.metoo.nspm.core.manager.admin.tools.DateTools;
import com.metoo.nspm.core.service.api.zabbix.ZabbixService;
import com.metoo.nspm.core.service.zabbix.IGatherService;
import com.metoo.nspm.core.service.zabbix.IProblemService;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.entity.nspm.Arp;
import com.metoo.nspm.entity.nspm.IpAddress;
import com.metoo.nspm.entity.nspm.Mac;
import com.metoo.nspm.entity.nspm.Route;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.*;

/**
 * @EnableScheduling：Spring系列框架中SpringFramwork自带的定时任务（org.springframework.scheduling.annotation.*）
 *
 * 注意事项：
 *  1：@Scheduled 多个任务使用了该方法，也是一个执行完执行下一个，并非并行执行；原因是scheduled默认线程数为1；
 *  2：每个定时任务才能执行下一次，禁止异步执行（@EnableAsync）
 *  3：并发执行，注意第“1”项里说明的，任务未执行完毕，另一个线程又来执行
 *
 */


@EnableScheduling
@Configuration // 用于标记配置类，兼备Component
public class SaticScheduleTask {

    Logger log = LoggerFactory.getLogger(SaticScheduleTask.class);

    @Value("${task.switch.is-open}")
    private boolean flag;
    @Autowired
    private ZabbixService zabbixService;
    @Autowired
    private IProblemService problemService;
    @Autowired
    private IArpHistoryService arpHistoryService;
    @Autowired
    private IMacHistoryService macHistoryService;
    @Autowired
    private IRoutHistoryService routHistoryService;
    @Autowired
    private IIPAddressHistoryService iipAddressHistoryService;
    @Autowired
    private IGatherService gatherService;

    static DefaultWebSecurityManager manager = new DefaultWebSecurityManager();

//
    // 添加定时任务
    @Scheduled(cron = "0 */1 * * * ?")
    public void configureTask(){
//        ThreadContext.bind(manager);
        //下面正常使用业务代码即可
        if(flag){
            Long time=System.currentTimeMillis();
            System.out.println("Arp开始采集");
            // 采集时间
            Calendar cal = Calendar.getInstance();
            cal.clear(Calendar.SECOND);
            cal.clear(Calendar.MILLISECOND);
            Date date = cal.getTime();
            // 此处开启两个线程
            // 存在先后顺序，先录取arp，在根据arp解析数据

            try {
//                this.zabbixService.gatherArp(date);
                this.gatherService.gatherArpItem(date);
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println("===Arp采集耗时：" + (System.currentTimeMillis()-time) + "===");
//
//            try {
//                this.gatherService.gatherMacItem(date);
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//
//            try {
//                this.gatherService.gatherIpaddressItem(date);
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//
//            try {
//                this.zabbixService.gatherProblem();
//            } catch (Exception e) {
//                e.printStackTrace();
//            }

        }
    }

    @Scheduled(cron = "0 */2 * * * ?")
    // 添加定时任务
    public void gatherMac(){
//        ThreadContext.bind(manager);
        //下面正常使用业务代码即可
        if(flag){
            Long time=System.currentTimeMillis();
            System.out.println("Mac开始采集");
            // 采集时间
            Calendar cal = Calendar.getInstance();
            cal.clear(Calendar.SECOND);
            cal.clear(Calendar.MILLISECOND);
            Date date = cal.getTime();
            try {
                this.gatherService.gatherMacItem(date);
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println("===Mac采集耗时：" + (System.currentTimeMillis()-time) + "===");
        }
    }

    @Scheduled(cron = "0 */1 * * * ?")
    // 添加定时任务
    public void gatherIpAddress(){
//        ThreadContext.bind(manager);
        //下面正常使用业务代码即可
        if(flag){
            Long time=System.currentTimeMillis();
            System.out.println("IpAddress开始采集");
            // 采集时间
            Calendar cal = Calendar.getInstance();
            cal.clear(Calendar.SECOND);
            cal.clear(Calendar.MILLISECOND);
            Date date = cal.getTime();
            try {
                this.gatherService.gatherIpaddressItem(date);
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println("===IpAddress采集耗时：" + (System.currentTimeMillis()-time) + "===");
        }
    }

//     采集 zabbix problem
//    @Scheduled(cron = "0 */1 * * * ?")
    @Scheduled(cron = "*/10 * * * * ?")
//    public void gatherProblem(){
////        ThreadContext.bind(manager);
//        //下面正常使用业务代码即可
//        if(flag) {
//            // 采集时间
//            Calendar cal = Calendar.getInstance();
//            cal.clear(Calendar.SECOND);
//            cal.clear(Calendar.MILLISECOND);
//            Date date = cal.getTime();
//            this.zabbixService.gatherProblem();
////            try {
////                this.zabbixService.gatherProblem();
////            } catch (Exception e) {
////                e.printStackTrace();
////            }
//        }
//    }

    @Scheduled(cron = "*/10 * * * * ?")
    public void gatherThreadProblem(){
//        ThreadContext.bind(manager);
        //下面正常使用业务代码即可
        if(flag) {
            // 采集时间
            Long begin = System.currentTimeMillis();
//            this.zabbixService.gatherThreadProblem();
            this.zabbixService.gatherProblem();
            Long end = System.currentTimeMillis();
            log.info("执行时间：" + (end - begin));
        }
    }

//    @Scheduled(cron = "0 */1 * * * ?")
//    public void updateProblemStatus(){
//        System.out.println("执行更新problem");
//        this.zabbixService.updateProblemStatus();
//    }

    @Scheduled(cron = "0 */1 * * * ?")
    // 添加定时任务
    public void updateRout(){
//        ThreadContext.bind(manager);
        if(flag) {
            Map params = new HashMap();
            Calendar calendar = Calendar.getInstance();
            params.put("endClock", DateTools.getTimesTamp10(calendar.getTime()));
            calendar.add(Calendar.MINUTE, -1);
            params.put("startClock", DateTools.getTimesTamp10(calendar.getTime()));
            int count = this.problemService.selectCount(params);
//            if(count > 0){
            if(true){
                Long time=System.currentTimeMillis();
                System.out.println("Rout开始采集");
                try {
                    Calendar cal = Calendar.getInstance();
                    cal.clear(Calendar.SECOND);
                    cal.clear(Calendar.MILLISECOND);
//                    this.zabbixService.gatherRout(cal.getTime());
                    this.gatherService.gatherRouteItem(cal.getTime());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                System.out.println("===Rout采集耗时：" + (System.currentTimeMillis()-time) + "===");
            }
        }
    }

    @Scheduled(cron = "0 0 0 */1 * ?")
    // 添加定时任务
    public void clearHistory(){
//        ThreadContext.bind(manager);
        if(flag) {
            Long time=System.currentTimeMillis();
            System.out.println("删除历史数据开始");
            Map params = new HashMap();
            params.put("beforeTime", new Date());
            try {
                List<Arp> arps = this.arpHistoryService.selectObjByMap(params);
                if(arps.size() > 0){
                    this.arpHistoryService.batchDelete(arps);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            try {
                List<Mac> macs = this.macHistoryService.selectObjByMap(params);
                if(macs.size() > 0){
                    this.macHistoryService.batchDelete(macs);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            try {
                List<Route> routList = this.routHistoryService.selectObjByMap(params);
                if(routList.size() > 0){
                    this.routHistoryService.batchDelete(routList);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            try {
                List<IpAddress> ipAddresses = this.iipAddressHistoryService.selectObjByMap(params);
                if(ipAddresses.size() > 0){
                    this.iipAddressHistoryService.batchDelete(ipAddresses);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println("==删除数据耗时：" + (System.currentTimeMillis()-time) + "===");
        }
    }




}
